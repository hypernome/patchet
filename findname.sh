checkdev () { curl -s https://api.domainsdb.info/v1/domains/search?domain=$1.dev | grep -q '"domain":' && echo taken || echo free; }

checkcom () { curl -s https://api.domainsdb.info/v1/domains/search?domain=$1.com | grep -q '"domain":' && echo taken || echo free; }

for w in matroid gammoid hypertree mobius weyl; do echo -n "$w.dev – "; checkdev $w; done

for w in matroid gammoid hypertree mobius weyl; do echo -n "$w.com – "; checkcom $w; done