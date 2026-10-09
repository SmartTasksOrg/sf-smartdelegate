"""Deterministic data for the Kestrel Works database (schema.sql).

    python3 -m live.upstream.seed [--dsn DSN] [--seed 20261005] [--scale 1.0] [--force]

The DSN comes from --dsn, SD_PG_DSN, or `pg.sh url`. The same seed and scale
always give the same rows (random.Random, no clock, no host data), so nothing
generated has to be kept in the repository. Two tenants (`kestrel`, the
company of examples/company, and `osprey`, somebody else's) and three regions
(EU, US, APAC). The 35 people of examples/company/entities.json are the first
employees, with their real ids, so that `requested_by`, `owner` and
`manager` point at users the engine knows.

Every sensitive value has a shape of its own, so a test can search anything
an agent received for it:
    card numbers       4929 0000 nnnn nnnn written without spaces
    IBANs              <CC>00KEST followed by 14 digits
    national ids       NID- and 9 digits
    tax ids            TAX- and 9 digits
    MFA-like secrets   are not in this schema
"""
from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
COMPANY = ROOT / "examples" / "company"
DEFAULT_SEED = 20261005
REGIONS = ("EU", "US", "APAC")
CURRENCY = {"EU": "EUR", "US": "USD", "APAC": "USD"}
TENANTS = (("kestrel", 0.8), ("osprey", 0.2))
BASE = {"customers": 3000, "tickets": 4000, "refunds": 1500, "vendors": 300, "purchase_orders": 800, "invoices": 1500,
        "payments": 1000, "extra_employees": 300, "opportunities": 1200, "contracts": 600}

FIRST = ("Ada", "Bo", "Cy", "Dana", "Eli", "Fay", "Gus", "Hana", "Ivo", "Jun", "Kai", "Lea", "Mio", "Nia", "Odd", "Pat", "Quy", "Rui", "Sam",
         "Tea", "Udo", "Vera", "Wim", "Xan", "Yui", "Zoe")
LAST = ("Abara", "Berg", "Castro", "Dahl", "Evans", "Fischer", "Garcia", "Hoang", "Ito", "Jansen", "Kim", "Lopez", "Meyer", "Novak", "Okoye",
        "Patel", "Quinn", "Rossi", "Sato", "Tran", "Usman", "Vega", "Weiss", "Xu", "Young", "Zhang")
CITY = {"EU": ("Ghent", "Lyon", "Porto", "Graz", "Turku"), "US": ("Tulsa", "Boise", "Macon", "Fargo", "Reno"), "APAC": ("Osaka", "Pune", "Cebu", "Perth", "Busan")}
WORDS = ("invoice", "delivery", "pallet", "refund", "damaged", "late", "duplicate", "address", "login", "contract", "renewal", "discount",
         "warranty", "return", "missing", "wrong", "item", "carrier", "customs", "credit")
TIERS = ("bronze", "silver", "gold", "platinum")


def dsn_from_env(explicit: str | None = None) -> str:
    if explicit:
        return explicit
    if os.environ.get("SD_PG_DSN"):
        return os.environ["SD_PG_DSN"]
    try:
        p = subprocess.run([str(HERE / "pg.sh"), "url"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        raise SystemExit(f"seed: cannot run pg.sh url: {e}")
    if p.returncode != 0:
        raise SystemExit("seed: no database: set SD_PG_DSN or run live/upstream/pg.sh start")
    return p.stdout.strip()


def digits(r: random.Random, n: int) -> str:
    return "".join(r.choice("0123456789") for _ in range(n))


def iban(r: random.Random, region: str) -> str:
    return {"EU": "DE", "US": "US", "APAC": "JP"}[region] + "00KEST" + digits(r, 14)


def sentence(r: random.Random, n: int) -> str:
    return " ".join(r.choice(WORDS) for _ in range(n))


def generate(seed: int = DEFAULT_SEED, scale: float = 1.0) -> dict:
    """-> {table: (columns, rows)}. Pure: no database, no clock."""
    r = random.Random(seed)
    n = {k: max(12, int(v * scale)) for k, v in BASE.items()}
    people = [e for e in json.loads((COMPANY / "entities.json").read_text(encoding="utf-8")) if e["uid"]["type"] == "User"]
    users_by_unit: dict = {}
    for e in people:
        users_by_unit.setdefault(e["attrs"]["unit"], []).append(e["uid"]["id"])
    support, sales, procurement, finance = (users_by_unit[u] for u in ("support", "sales", "procurement", "finance"))
    out: dict = {}

    def tenant() -> str:
        return "kestrel" if r.random() < TENANTS[0][1] else "osprey"

    def person() -> str:
        return f"{r.choice(FIRST)} {r.choice(LAST)}"

    customers = []
    for i in range(1, n["customers"] + 1):
        t, region, name = tenant(), r.choice(REGIONS), person()
        addresses = [{"street": f"{r.randint(1, 400)} {r.choice(LAST)} St", "city": r.choice(CITY[region]), "zip": digits(r, 5),
                      "geo": {"lat": round(r.uniform(-60, 60), 4), "lng": round(r.uniform(-170, 170), 4)}} for _ in range(r.randint(1, 3))]
        card = "49290000" + digits(r, 8)
        customers.append((f"c-{i:05d}", t, name, f"{name.split()[0].lower()}.{i}@customers.example", f"+{r.randint(1, 98)} {digits(r, 9)}",
                          region, r.choice(TIERS), f"internal: {sentence(r, 6)}", json.dumps(addresses), card[-4:], card,
                          r.choice(support) if r.random() < 0.02 else None))
    out["customers"] = ("id tenant name email phone region tier notes addresses card_last4 card_number owner_user".split(), customers)
    by_tenant = {t: [c for c in customers if c[1] == t] for t, _ in TENANTS}

    tickets = []
    for i in range(1, n["tickets"] + 1):
        c = r.choice(customers)
        tickets.append((f"t-{i:05d}", c[1], c[0], c[5], sentence(r, 4), f"{c[2]} wrote: {sentence(r, 30)}", r.choice(("open", "pending", "closed")),
                        r.choice(("low", "normal", "high")), f"triage: {sentence(r, 5)}"))
    out["tickets"] = ("id tenant customer_id region subject body status priority internal_notes".split(), tickets)

    refunds = []
    for i in range(1, n["refunds"] + 1):
        c = r.choice(customers)
        refunds.append((f"r-{i:05d}", c[1], f"o-{r.randint(1, 99999):05d}", c[0], c[5], r.randint(500, 60000), CURRENCY[c[5]], sentence(r, 3),
                        r.choice(("requested", "approved", "paid")), r.choice(support), f"fraud score 0.{r.randint(0, 99):02d}", "seed"))
    out["refunds"] = ("id tenant order_id customer_id region amount currency reason status requested_by internal_note origin".split(), refunds)

    vendors = []
    for i in range(1, n["vendors"] + 1):
        region = r.choice(REGIONS)
        vendors.append((f"v-{i:04d}", tenant(), f"{r.choice(LAST)} {r.choice(('Supply', 'Logistics', 'Tools', 'Packaging', 'Freight'))}", region,
                        r.choice(("active", "pending", "blocked")), r.choice(procurement), f"ap.{i}@vendors.example", "TAX-" + digits(r, 9),
                        r.randint(1, 99), "KEST" + region[:2] + "2X", iban(r, region)))
    out["vendors"] = ("id tenant name region status onboarded_by contact_email tax_id risk_score bank_bic bank_iban".split(), vendors)
    vendors_of = {t: [v for v in vendors if v[1] == t] for t, _ in TENANTS}

    pos = []
    for i in range(1, n["purchase_orders"] + 1):
        v = r.choice(vendors)
        items = [{"sku": f"SKU-{r.randint(100, 999)}", "qty": r.randint(1, 40), "unit_price": r.randint(200, 90000)} for _ in range(r.randint(1, 5))]
        requester = r.choice(procurement)
        approver = r.choice([p for p in ("wendy", "xavier") if p != requester] or ["wendy"])
        approved = r.random() < 0.6
        pos.append((f"po-{i:05d}", v[1], v[0], f"CC-{r.choice((100, 200, 300, 400, 500, 600, 700))}", requester, approver if approved else None,
                    "approved" if approved else "draft", sum(x["qty"] * x["unit_price"] for x in items), CURRENCY[v[3]], json.dumps(items)))
    out["purchase_orders"] = ("id tenant vendor_id cost_center requested_by approved_by status amount currency items".split(), pos)
    pos_of = {t: [p for p in pos if p[1] == t] for t, _ in TENANTS}

    invoices = []
    for i in range(1, n["invoices"] + 1):
        t = tenant()
        v = r.choice(vendors_of[t])
        po = r.choice(pos_of[t]) if pos_of[t] and r.random() < 0.7 else None
        lines = [{"text": sentence(r, 3), "amount": r.randint(1000, 250000)} for _ in range(r.randint(1, 6))]
        invoices.append((f"inv-{i:05d}", t, v[0], po[0] if po else None, sum(x["amount"] for x in lines), CURRENCY[v[3]],
                         r.choice(("received", "matched", "paid")), json.dumps(lines), v[2], v[10]))
    out["invoices"] = ("id tenant vendor_id po_id amount currency status lines remit_to_name remit_to_iban".split(), invoices)

    payments = []
    for i in range(1, n["payments"] + 1):
        t = tenant()
        v = r.choice(vendors_of[t])
        requester = r.choice(procurement)
        payments.append((f"pay-{i:05d}", t, r.choice(("po", "refund")), f"po-{r.randint(1, n['purchase_orders']):05d}", v[0], r.randint(1000, 900000),
                         CURRENCY[v[3]], r.choice(("scheduled", "sent")), requester, r.choice(("wendy", "xavier")), r.choice(finance), v[2], v[10], "seed"))
    out["payments"] = ("id tenant kind ref vendor_id amount currency status requested_by approved_by paid_by beneficiary_name beneficiary_iban origin".split(), payments)

    employees, salaries = [], []

    def employee(eid, t, name, unit, region, manager, title):
        employees.append((eid, t, name, f"{eid}@{t}.example", unit, region, manager, title, f"20{r.randint(10, 25)}-{r.randint(1, 12):02d}-{r.randint(1, 28):02d}",
                          "active" if r.random() < 0.93 else "left", "NID-" + digits(r, 9), f"{r.randint(1, 200)} {r.choice(LAST)} Rd, {r.choice(CITY[region])}",
                          iban(r, region), json.dumps({"name": person(), "phone": f"+{r.randint(1, 98)} {digits(r, 9)}"})))
        salaries.append((eid, t, CURRENCY[region], f"G{r.randint(3, 12)}", r.randint(2800000, 14000000), r.randint(0, 2000000), f"hr: {sentence(r, 5)}"))

    for e in people:
        a = e["attrs"]
        employee(e["uid"]["id"], "kestrel", a["name"], a["unit"], a["region"], a.get("manager"), a["title"])
    units = sorted(users_by_unit)
    for i in range(1, n["extra_employees"] + 1):
        t = tenant()
        unit = r.choice(units)
        employee(f"e-{i:05d}", t, person(), unit, r.choice(REGIONS), r.choice(users_by_unit[unit]) if t == "kestrel" else None, r.choice(("Analyst", "Clerk", "Engineer", "Coordinator")))
    out["employees"] = ("id tenant name email unit region manager job_title start_date status national_id home_address bank_account emergency_contact".split(), employees)
    out["salaries"] = ("employee_id tenant currency grade base bonus notes".split(), salaries)

    opportunities = []
    for i in range(1, n["opportunities"] + 1):
        c = r.choice(customers)
        opportunities.append((f"opp-{i:05d}", c[1], c[0], c[5], r.choice(sales), r.choice(("lead", "quote", "won", "lost")), r.randint(50000, 9000000),
                              r.randint(0, 35), f"deal notes: {sentence(r, 6)}"))
    out["opportunities"] = ("id tenant customer_id region owner stage amount discount_pct notes".split(), opportunities)

    contracts = []
    for i in range(1, n["contracts"] + 1):
        c = r.choice(customers)
        clauses = [{"n": k + 1, "text": sentence(r, 8)} for k in range(r.randint(2, 6))]
        contracts.append((f"ct-{i:05d}", c[1], c[0], c[5], r.choice(("draft", "signed", "expired")), r.choice((12, 24, 36)), json.dumps(clauses), person(),
                          r.randint(100000, 9000000), r.randint(0, 30), r.randint(5, 60)))
    out["contracts"] = ("id tenant customer_id region status term_months clauses signatory list_price discount_pct margin_pct".split(), contracts)
    assert by_tenant["kestrel"] and by_tenant["osprey"]
    return out


def load(dsn: str, seed: int = DEFAULT_SEED, scale: float = 1.0, force: bool = False) -> int:
    """Create the schema and load the rows. A database that already holds this
    seed and scale is left alone unless `force`. Returns the row count."""
    import psycopg2
    from psycopg2.extras import execute_values

    conn = psycopg2.connect(dsn, connect_timeout=15)
    try:
        cur = conn.cursor()
        cur.execute("select to_regclass('company.seed_info')")
        if cur.fetchone()[0] and not force:
            cur.execute("select seed, scale, rows from company.seed_info")
            row = cur.fetchone()
            if row and row[0] == seed and abs(row[1] - scale) < 1e-9:
                conn.rollback()
                return int(row[2])
        cur.execute((HERE / "schema.sql").read_text(encoding="utf-8"))
        total = 0
        for table, (columns, rows) in generate(seed, scale).items():
            execute_values(cur, f"insert into company.{table} ({', '.join(columns)}) values %s", rows, page_size=1000)
            total += len(rows)
        cur.execute("insert into company.seed_info (seed, scale, rows) values (%s, %s, %s)", (seed, scale, total))
        conn.commit()
        cur.execute("analyze")
        conn.commit()
        return total
    finally:
        conn.close()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dsn")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--scale", type=float, default=1.0)
    ap.add_argument("--force", action="store_true", help="drop and reload even when this seed is already loaded")
    ap.add_argument("--count", action="store_true", help="print the row counts the generator produces and exit (no database)")
    a = ap.parse_args(argv)
    if a.count:
        for table, (_, rows) in generate(a.seed, a.scale).items():
            print(f"{table:18} {len(rows)}")
        return 0
    total = load(dsn_from_env(a.dsn), a.seed, a.scale, a.force)
    print(f"seed {a.seed} scale {a.scale}: {total} rows in schema company")
    return 0


if __name__ == "__main__":
    sys.exit(main())
