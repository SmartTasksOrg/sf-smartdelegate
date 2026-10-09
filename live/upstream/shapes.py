"""Database row -> the JSON record the upstream systems return. The shapes
follow examples/company/catalog.json: nested where the catalog nests
(`card.number`, `bank.iban`, `remit_to.iban`, `pricing.margin_pct`), plus a
few keys the catalog does not list at all (`tenant`, `_links`, `audit`), the
way a real API returns more than anybody catalogued."""
from __future__ import annotations

#: resource name in the API -> (table, catalog path, key column)
RESOURCES = {
    "customers": ("customers", "crm.customer", "id"),
    "tickets": ("tickets", "crm.ticket", "id"),
    "refunds": ("refunds", "billing.refund", "id"),
    "invoices": ("invoices", "billing.invoice", "id"),
    "payments": ("payments", "finance.payment", "id"),
    "employees": ("employees", "hr.employee", "id"),
    "salaries": ("salaries", "hr.salary", "employee_id"),
    "vendors": ("vendors", "procurement.vendor", "id"),
    "opportunities": ("opportunities", "sales.opportunity", "id"),
    "contracts": ("contracts", "sales.contract", "id"),
    "purchase-orders": ("purchase_orders", "procurement.po", "id"),
}


def shape(resource: str, row: dict) -> dict:
    r = dict(row)
    r.pop("origin", None)
    if resource == "customers":
        r["card"] = {"last4": r.pop("card_last4"), "number": r.pop("card_number")}
        r.pop("owner_user", None)
        r["_links"] = {"self": f"/{r['tenant']}/customers/{r['id']}"}
    elif resource == "vendors":
        r["bank"] = {"bic": r.pop("bank_bic"), "iban": r.pop("bank_iban")}
    elif resource == "invoices":
        r["remit_to"] = {"name": r.pop("remit_to_name"), "iban": r.pop("remit_to_iban")}
    elif resource == "payments":
        r["beneficiary"] = {"name": r.pop("beneficiary_name"), "iban": r.pop("beneficiary_iban")}
    elif resource == "contracts":
        r["pricing"] = {"list_price": r.pop("list_price"), "discount_pct": r.pop("discount_pct"), "margin_pct": r.pop("margin_pct")}
    return r
