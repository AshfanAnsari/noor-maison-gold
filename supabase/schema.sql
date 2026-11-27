-- =====================================================================
-- Noor Maison by Saba — Supabase schema (run once, in the SQL editor of
-- SABA'S OWN Supabase project, region Mumbai / ap-south-1)
-- ---------------------------------------------------------------------
-- What lives here:
--   products   — every piece the website sells. The website READS this
--                table live; Saba EDITS it from her admin (prices,
--                photos, stock). One table replaces the product data
--                that used to be baked into the site's HTML files.
--   enquiries  — "Talk to Saba" messages from the website.
--   orders     — orders placed on the website (UPI flow: Saba confirms
--                payment herself before dispatch, as always).
--
-- Security model (read this before changing any policy):
--   * The website uses the PUBLIC anon key. That key is not a secret —
--     it ships in the page. Safety comes from Row Level Security (RLS):
--     every table below has RLS ON, and the public can only do exactly
--     what the policies say — read live products, send an enquiry,
--     place an order. Nothing else.
--   * The service_role key bypasses RLS completely. It must NEVER
--     appear in website code, the admin page, or any public file.
--   * "Admin" = a signed-in user whose email is Saba's. Her email is
--     written into the policies on purpose — one shop, one owner, and
--     the next developer can see the rule at a glance. If Saba ever
--     changes her email, update ADMIN_EMAIL in the function below.
-- =====================================================================

-- The one place that decides who the admin is.
create or replace function public.is_admin()
returns boolean
language sql stable
as $$
  select coalesce(auth.jwt() ->> 'email', '') = 'noormaisonbysaba@gmail.com';
$$;

-- ---------------------------------------------------------------------
-- PRODUCTS
--   price / mrp are whole rupees. NULL price = "no price yet" and the
--   website simply shows no price (it never invents one). mrp is only
--   filled when Saba gives a genuine MRP — the site shows the struck
--   MRP + % off only when mrp > price.
--   stock: NULL = plenty (site shows nothing), 0 = Out of stock
--   (ordering switches off), 1..4 = the site shows "Only X left".
--   photos: first entry is the main photo; the rest follow in the
--   gallery. New photos Saba uploads land in the product-photos
--   storage bucket and their URLs are appended here.
-- ---------------------------------------------------------------------
create table public.products (
  id          text primary key,              -- the site's own ids: cat-1, prod-3, turk-2 …
  name        text not null,
  category    text not null,                 -- Earrings / Necklace Set / Bracelet / Ring / Nail Set
  description text,
  finish      text,                          -- spec line on the product page
  stones      text,                          -- spec line on the product page
  price       integer check (price is null or price >= 0),
  mrp         integer check (mrp is null or mrp >= 0),
  stock       integer check (stock is null or stock >= 0),
  photos      text[] not null default '{}',
  videos      text[] not null default '{}',
  sort        integer not null default 0,    -- catalogue order on Explore
  is_active   boolean not null default true, -- Saba can hide a piece without deleting it
  updated_at  timestamptz not null default now()
);

alter table public.products enable row level security;

-- Anyone (the website, with the public key) may read pieces that are live.
create policy "public reads live products"
  on public.products for select
  to anon, authenticated
  using (is_active = true);

-- Only Saba (signed in) may change anything.
create policy "admin manages products"
  on public.products for all
  to authenticated
  using (public.is_admin())
  with check (public.is_admin());

-- ---------------------------------------------------------------------
-- ENQUIRIES — customers write, only Saba reads.
-- consent must be true (the site's form asks before sending — DPDP).
-- ---------------------------------------------------------------------
create table public.enquiries (
  id         uuid primary key default gen_random_uuid(),
  name       text not null,
  phone      text not null,
  message    text not null,
  product_id text,                            -- optional: the piece they asked about
  consent    boolean not null default false,
  is_done    boolean not null default false,  -- Saba ticks it off in her admin
  created_at timestamptz not null default now()
);

alter table public.enquiries enable row level security;

create policy "public sends enquiries"
  on public.enquiries for insert
  to anon, authenticated
  with check (consent = true and length(name) >= 2 and length(phone) >= 10);

create policy "admin manages enquiries"
  on public.enquiries for all
  to authenticated
  using (public.is_admin())
  with check (public.is_admin());

-- ---------------------------------------------------------------------
-- ORDERS — placed on the website; payment is by UPI after Saba
-- confirms (order_code goes in the UPI note so she can match them).
-- status flow: new → confirmed → dispatched → done (or cancelled).
-- amount is filled by the site only when the piece has a real price.
-- ---------------------------------------------------------------------
create table public.orders (
  id           uuid primary key default gen_random_uuid(),
  order_code   text not null unique,          -- e.g. NM-AB12CD, shown to the customer
  product_id   text not null,
  product_name text not null,                 -- copied at order time; history must not change if Saba renames a piece
  qty          integer not null default 1 check (qty >= 1),
  amount       integer,                       -- rupees, NULL while the piece has no price
  name         text not null,
  phone        text not null,
  address      text not null,
  status       text not null default 'new'
               check (status in ('new', 'confirmed', 'dispatched', 'done', 'cancelled')),
  created_at   timestamptz not null default now()
);

alter table public.orders enable row level security;

create policy "public places orders"
  on public.orders for insert
  to anon, authenticated
  with check (length(name) >= 2 and length(phone) >= 10 and length(address) >= 10);

create policy "admin manages orders"
  on public.orders for all
  to authenticated
  using (public.is_admin())
  with check (public.is_admin());

-- ---------------------------------------------------------------------
-- STORAGE — one public bucket for the photos Saba uploads herself.
-- Public READ (the website shows them); only Saba can add/replace/
-- delete. The catalogue photos that already exist stay where they are
-- (in the website repo); this bucket is for her new uploads.
-- ---------------------------------------------------------------------
insert into storage.buckets (id, name, public)
values ('product-photos', 'product-photos', true)
on conflict (id) do nothing;

create policy "public reads product photos"
  on storage.objects for select
  to anon, authenticated
  using (bucket_id = 'product-photos');

create policy "admin manages product photos"
  on storage.objects for all
  to authenticated
  using (bucket_id = 'product-photos' and public.is_admin())
  with check (bucket_id = 'product-photos' and public.is_admin());

-- ---------------------------------------------------------------------
-- TABLE GRANTS — the layer UNDER the policies. RLS decides row by
-- row, but a role first needs the table-level grant to touch a table
-- at all. Newer Supabase projects do NOT auto-grant tables created in
-- the SQL editor, so these grants are part of the schema on purpose.
-- The grants mirror the policies: the public can only do what the
-- matching policy also allows — two locks on the same door.
-- ---------------------------------------------------------------------
grant select on public.products to anon, authenticated;
grant insert, update, delete on public.products to authenticated;

grant insert on public.enquiries to anon, authenticated;
grant select, update, delete on public.enquiries to authenticated;

grant insert on public.orders to anon, authenticated;
grant select, update on public.orders to authenticated;

-- =====================================================================
-- After running this file:
--   1. Authentication → Providers → Google: turn ON (client id/secret
--      from Saba's own Google Cloud project) so her admin gets the
--      "Continue with Google" button. Email+password works without it.
--   2. Create Saba's user (Authentication → Users → Add user) with her
--      email, so she can sign in the moment the admin goes live.
--   3. Load seed-products.json into `products` (Table editor → Import,
--      or the seed script in this folder).
--   4. Run the security proof (README, step "prove it"): with ONLY the
--      anon key, reading enquiries/orders must return nothing and
--      editing a product must fail.
-- =====================================================================
