-- Kestrel Works, the company of examples/company, as a relational database.
-- One table per catalogued resource the live tests use. Column names equal the
-- catalog's field names wherever the field is a plain name, so that SqlGuard
-- can be pointed at the tables; nested catalog fields (card.number,
-- bank.iban, remit_to.iban, pricing.*) are flat columns here and are nested
-- again by the REST API. Every table has a `tenant` column, and holds rows of
-- more than one tenant. Money is in minor units.
drop schema if exists company cascade;
create schema company;
set search_path = company;

create table customers (
  id text primary key, tenant text not null, name text not null, email text not null, phone text not null,
  region text not null, tier text not null, notes text not null, addresses jsonb not null,
  card_last4 text not null, card_number text not null, owner_user text
);
create table tickets (
  id text primary key, tenant text not null, customer_id text not null references customers(id), region text not null,
  subject text not null, body text not null, status text not null, priority text not null, internal_notes text not null
);
create table refunds (
  id text primary key, tenant text not null, order_id text not null, customer_id text not null references customers(id),
  region text not null, amount bigint not null check (amount >= 0), currency text not null, reason text not null,
  status text not null, requested_by text not null, internal_note text not null, origin text not null default 'seed'
);
create table vendors (
  id text primary key, tenant text not null, name text not null, region text not null, status text not null,
  onboarded_by text not null, contact_email text not null, tax_id text not null, risk_score integer not null,
  bank_bic text not null, bank_iban text not null
);
create table purchase_orders (
  id text primary key, tenant text not null, vendor_id text not null references vendors(id), cost_center text not null,
  requested_by text not null, approved_by text, status text not null, amount bigint not null, currency text not null,
  items jsonb not null
);
create table invoices (
  id text primary key, tenant text not null, vendor_id text not null references vendors(id), po_id text,
  amount bigint not null, currency text not null, status text not null, lines jsonb not null,
  remit_to_name text not null, remit_to_iban text not null
);
create table payments (
  id text primary key, tenant text not null, kind text not null, ref text not null, vendor_id text,
  amount bigint not null check (amount >= 0), currency text not null, status text not null, requested_by text not null,
  approved_by text not null, paid_by text, beneficiary_name text not null, beneficiary_iban text not null,
  origin text not null default 'seed'
);
create table employees (
  id text primary key, tenant text not null, name text not null, email text not null, unit text not null,
  region text not null, manager text, job_title text not null, start_date text not null, status text not null,
  national_id text not null, home_address text not null, bank_account text not null, emergency_contact jsonb not null
);
create table salaries (
  employee_id text primary key references employees(id), tenant text not null, currency text not null,
  grade text not null, base bigint not null, bonus bigint not null, notes text not null
);
create table opportunities (
  id text primary key, tenant text not null, customer_id text not null references customers(id), region text not null,
  owner text not null, stage text not null, amount bigint not null, discount_pct integer not null, notes text not null
);
create table contracts (
  id text primary key, tenant text not null, customer_id text not null references customers(id), region text not null,
  status text not null, term_months integer not null, clauses jsonb not null, signatory text not null,
  list_price bigint not null, discount_pct integer not null, margin_pct integer not null
);

create index on customers (tenant, region);
create index on tickets (tenant, region);
create index on refunds (tenant, region);
create index on opportunities (tenant, region);
create index on contracts (tenant, region);

-- what the REST API saw: one row per request it answered. The tests read it
-- to prove what did (and did not) reach the upstream. Header *names* only.
create table api_request_log (
  n bigserial primary key, at timestamptz not null default now(), method text not null, path text not null,
  query text not null, status integer not null, key_ok boolean not null, had_authorization boolean not null,
  header_names text not null
);

-- SqlGuard takes one unqualified table name and knows nothing about tenants:
-- it is pointed at one view per tenant and table (see live/README.md).
create view kestrel_customers as select id, name, email, phone, region, tier, notes, addresses, card_last4, card_number from customers where tenant = 'kestrel';
create view kestrel_tickets as select id, customer_id, region, subject, body, status, priority, internal_notes from tickets where tenant = 'kestrel';
create view kestrel_refunds as select id, order_id, customer_id, region, amount, currency, reason, status, requested_by, internal_note from refunds where tenant = 'kestrel';
create view kestrel_vendors as select id, name, region, status, onboarded_by, contact_email, tax_id, risk_score, bank_bic, bank_iban from vendors where tenant = 'kestrel';
create view kestrel_employees as select id, name, email, unit, region, manager, job_title, start_date, status, national_id, home_address, bank_account, emergency_contact from employees where tenant = 'kestrel';
create view kestrel_salaries as select employee_id, currency, grade, base, bonus, notes from salaries where tenant = 'kestrel';
create view kestrel_invoices as select id, vendor_id, po_id, amount, currency, status, lines, remit_to_name, remit_to_iban from invoices where tenant = 'kestrel';
create view kestrel_purchase_orders as select id, vendor_id, cost_center, requested_by, approved_by, status, amount, currency, items from purchase_orders where tenant = 'kestrel';

create table seed_info (seed bigint not null, scale double precision not null, rows bigint not null, at timestamptz not null default now());
