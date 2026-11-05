"""Lista blanca de lo que puede aparecer en un caso público: si algo no está aquí, el caso no se publica.

Permitido: el seudónimo y sus subdominios, sus variantes (los parecidos), proveedores comunes, nombres
`.example` y las IP de documentación (RFC 5737 y 3849). Funciona sin el mapa de nombres reales, así que la
comprobación corre igual en el clon público.
"""

import ipaddress
import re

from auditor.tools.parecidos import variantes_validas

PROVEEDORES = frozenset({
    # correo
    "google.com", "googlemail.com", "gmail.com", "outlook.com", "microsoft.com", "office365.com", "hotmail.com",
    "zoho.com", "amazonses.com", "sendgrid.net", "mailgun.org", "mailchimp.com", "mcsv.net", "mandrillapp.com",
    "mimecast.com", "pphosted.com", "emailsrvr.com", "titan.email", "yahoo.com", "icloud.com", "hubspotemail.net",
    "zendesk.com", "salesforce.com", "exacttarget.com", "messagelabs.com", "barracudanetworks.com",
    # DNS, hosting y certificados
    "cloudflare.com", "cloudflare.net", "amazonaws.com", "awsdns-cn.com", "azure.com", "azurewebsites.net",
    "godaddy.com", "domaincontrol.com", "secureserver.net", "hostinger.com", "dns-parking.com", "hostgator.com",
    "bluehost.com", "siteground.net", "wix.com", "wixdns.net", "shopify.com", "myshopify.com", "squarespace.com",
    "wordpress.com", "github.io", "vercel.app", "netlify.app", "letsencrypt.org", "sectigo.com", "digicert.com",
    "globalsign.com", "googledomains.com", "registrar-servers.com", "name.com", "namecheap.com", "nic.co",
    "cointernet.co", "dnsmadeeasy.com", "ultradns.net", "nsone.net", "akam.net", "akamai.net", "fastly.net",
})
# Nombres con forma de dominio que no lo son.
NO_DOMINIOS = frozenset({"security.txt"})
REDES_DOCUMENTACION = tuple(ipaddress.ip_network(r) for r in
                            ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))

_ETIQUETA = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?"
TOKEN = re.compile(
    rf"(?P<correo>[\w.+-]+@(?:{_ETIQUETA}\.)+[a-z]{{2,63}})"
    r"|(?P<ip4>(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.]))"
    r"|(?P<ip6>(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:]))"
    rf"|(?P<dominio>(?<![\w.-])(?:{_ETIQUETA}\.)+[a-z]{{2,63}}(?![\w-]))",
    re.IGNORECASE)


def es_ip(texto: str) -> bool:
    try:
        ipaddress.ip_address(texto)
    except ValueError:
        return False
    return True


def ip_de_documentacion(texto: str) -> bool:
    ip = ipaddress.ip_address(texto)
    return any(ip.version == red.version and ip in red for red in REDES_DOCUMENTACION)


def dominio_permitido(dominio: str, permitidos: set[str]) -> bool:
    d = dominio.lower().rstrip(".")
    if d in NO_DOMINIOS or d == "example" or d.endswith(".example"):
        return True
    return any(d == p or d.endswith("." + p) for p in permitidos | PROVEEDORES)


def permitidos_para(seudonimo: str) -> set[str]:
    return {seudonimo} | variantes_validas(seudonimo)


def revisar_texto(texto: str, permitidos: set[str]) -> list[str]:
    """Dominios, IP y correos que no están permitidos, sin repetir y en orden de aparición."""
    malos: dict[str, None] = {}
    for m in TOKEN.finditer(texto):
        valor = m.group()
        if m.lastgroup == "correo":
            ok = dominio_permitido(valor.rsplit("@", 1)[1], permitidos)
        elif m.lastgroup in ("ip4", "ip6"):
            ok = not es_ip(valor) or ip_de_documentacion(valor)
        else:
            ok = dominio_permitido(valor, permitidos)
        if not ok:
            malos[valor] = None
    return list(malos)
