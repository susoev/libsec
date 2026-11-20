"""Каталог продуктов: что отслеживаем и как узнаём продукт в данных разных источников.

Поля продукта:
  slug, name, cat     — идентификатор, имя, категория
  cna                 — регэкспы (fullmatch, без регистра) по «vendor|product» из CVE-записи (affected[] CNA/ADP)
  cpe                 — «vendor:product» из CPE 2.3
  pkg                 — имена пакетов (affected[].packageName в CVE, дистрибутивы): точное совпадение или регэксп
  osv                 — {экосистема OSV: [имена пакетов]}
  kev                 — регэксп по «vendorProject|product» из CISA KEV
  high_only           — продукт с потоком мелких CVE (ядро Linux): в ленту только KEV или CVSS >= 7
"""
import re

CATS = {
    'lang': 'Languages & runtimes',
    'web': 'Web servers & proxies',
    'db': 'Databases & caches',
    'sys': 'System & crypto',
    'cont': 'Containers',
    'fw': 'Frameworks & CMS',
    'tools': 'Tooling & services',
}

P = [
    # --- языки и рантаймы
    dict(slug='php', name='PHP', cat='lang', cna=[r'php group\|php', r'php\|php', r'.*\|php-src'], cpe=['php:php'],
         pkg=[r'php(\d(\.\d+)?)?', 'php-src', r'php\d*-(fpm|cli|common)'], kev=r'php( group)?\|(php|fastcgi process manager \(fpm\))'),
    dict(slug='python', name='Python (CPython)', cat='lang', cna=[r'python software foundation\|cpython', r'python\|python'],
         cpe=['python:python'], pkg=[r'python(3)?(\.\d+)?', 'cpython'], kev=r'python\|python'),
    dict(slug='nodejs', name='Node.js', cat='lang', cna=[r'nodejs\|node(\.js)?', r'node\.js\|node\.js', r'openjs foundation\|node\.js'],
         cpe=['nodejs:node.js'], pkg=[r'nodejs(\d+)?'], kev=r'node\.?js\|.*'),
    dict(slug='ruby', name='Ruby', cat='lang', cna=[r'ruby\|ruby', r'ruby-lang\|ruby'], cpe=['ruby-lang:ruby'], pkg=[r'ruby(\d(\.\d)?)?']),
    dict(slug='openjdk', name='Java (OpenJDK / Java SE)', cat='lang', cna=[r'oracle( corporation)?\|(oracle )?java se.*', r'.*\|openjdk.*'],
         cpe=['oracle:jdk', 'oracle:jre', 'oracle:openjdk'], pkg=[r'(java-[\d.]+-)?openjdk.*'], kev=r'oracle\|java (se|runtime).*'),
    dict(slug='go', name='Go', cat='lang', cna=[r'go( standard library| toolchain)?\|.*', r'golang\|go'], cpe=['golang:go'],
         pkg=['golang'], osv={'Go': ['stdlib', 'toolchain']}),
    # --- веб-серверы и прокси
    dict(slug='nginx', name='nginx', cat='web', cna=[r'f5( networks)?\|nginx( open source| plus)?', r'nginx\|nginx'],
         cpe=['f5:nginx', 'nginx:nginx', 'f5:nginx_open_source', 'f5:nginx_plus'], pkg=['nginx'], kev=r'(f5|nginx)\|nginx.*'),
    dict(slug='apache-httpd', name='Apache HTTP Server', cat='web', cna=[r'apache software foundation\|apache http server', r'apache\|http server'],
         cpe=['apache:http_server'], pkg=['httpd', r'apache2'], kev=r'apache\|http server'),
    dict(slug='tomcat', name='Apache Tomcat', cat='web', cna=[r'apache software foundation\|apache tomcat'], cpe=['apache:tomcat'],
         pkg=[r'tomcat\d*'], osv={'Maven': ['org.apache.tomcat.embed:tomcat-embed-core', 'org.apache.tomcat:tomcat-catalina', 'org.apache.tomcat:tomcat-coyote']},
         kev=r'apache\|tomcat'),
    dict(slug='haproxy', name='HAProxy', cat='web', cna=[r'haproxy.*\|haproxy.*'], cpe=['haproxy:haproxy'], pkg=['haproxy']),
    dict(slug='caddy', name='Caddy', cat='web', cna=[r'caddyserver\|caddy'], cpe=['caddyserver:caddy'], osv={'Go': ['github.com/caddyserver/caddy/v2']}),
    dict(slug='varnish', name='Varnish Cache', cat='web', cna=[r'varnish.*\|varnish.*'], cpe=['varnish-cache:varnish_cache', 'varnish_cache_project:varnish_cache'], pkg=['varnish']),
    dict(slug='traefik', name='Traefik', cat='web', cna=[r'traefik.*\|traefik'], cpe=['traefik:traefik'],
         osv={'Go': ['github.com/traefik/traefik/v2', 'github.com/traefik/traefik/v3']}),
    # --- БД и кэши
    dict(slug='mysql', name='MySQL', cat='db', cna=[r'oracle( corporation)?\|mysql( server| cluster)?'], cpe=['oracle:mysql', 'oracle:mysql_server'],
         pkg=[r'mysql(-server)?(\d(\.\d)?)?', r'mysql\d*'], kev=r'oracle\|mysql.*'),
    dict(slug='mariadb', name='MariaDB', cat='db', cna=[r'mariadb.*\|mariadb.*'], cpe=['mariadb:mariadb'], pkg=[r'mariadb(-server)?(\d+(\.\d+)?)?']),
    dict(slug='postgresql', name='PostgreSQL', cat='db', cna=[r'(postgresql|n/a|the postgresql global development group)\|postgresql'],
         cpe=['postgresql:postgresql'], pkg=[r'postgresql(\d+)?'], kev=r'postgresql\|postgresql'),
    dict(slug='redis', name='Redis / Valkey', cat='db', cna=[r'redis.*\|redis', r'valkey.*\|valkey'], cpe=['redis:redis', 'redislabs:redis', 'lfprojects:valkey'],
         pkg=['redis', 'valkey'], kev=r'redis\|.*redis.*'),
    dict(slug='mongodb', name='MongoDB Server', cat='db', cna=[r'mongodb( inc\.?)?\|mongodb( server| enterprise server| community server)?'], cpe=['mongodb:mongodb'],
         pkg=[r'mongodb(-org)?(-server)?'], kev=r'mongodb\|mongodb( and mongodb server| server)?'),
    dict(slug='memcached', name='Memcached', cat='db', cna=[r'.*\|memcached'], cpe=['memcached:memcached'], pkg=['memcached']),
    dict(slug='elasticsearch', name='Elasticsearch / OpenSearch', cat='db', cna=[r'elastic\|elasticsearch', r'opensearch.*\|opensearch'],
         cpe=['elastic:elasticsearch', 'amazon:opensearch'], kev=r'elastic\|elasticsearch'),
    # --- системное
    dict(slug='openssl', name='OpenSSL', cat='sys', cna=[r'openssl\|openssl'], cpe=['openssl:openssl'], pkg=[r'openssl(\d+)?'], kev=r'openssl\|openssl'),
    dict(slug='openssh', name='OpenSSH', cat='sys', cna=[r'openbsd\|openssh', r'openssh\|openssh'], cpe=['openbsd:openssh'], pkg=['openssh', r'openssh-(server|client)'], kev=r'openbsd\|openssh'),
    dict(slug='glibc', name='glibc', cat='sys', cna=[r'(the )?gnu c library\|glibc', r'gnu\|glibc'], cpe=['gnu:glibc'], pkg=['glibc', r'libc6']),
    dict(slug='curl', name='curl / libcurl', cat='sys', cna=[r'curl\|curl', r'curl\|libcurl'], cpe=['haxx:curl', 'haxx:libcurl'], pkg=['curl', r'libcurl\d*']),
    dict(slug='sudo', name='sudo', cat='sys', cna=[r'sudo.*\|sudo'], cpe=['sudo_project:sudo', 'todd_miller:sudo'], pkg=['sudo'], kev=r'sudo\|sudo'),
    dict(slug='systemd', name='systemd', cat='sys', cna=[r'systemd.*\|systemd'], cpe=['systemd_project:systemd'], pkg=['systemd']),
    dict(slug='linux-kernel', name='Linux kernel', cat='sys', cna=[r'linux\|linux( kernel)?'], cpe=['linux:linux_kernel'], pkg=['kernel', r'linux(-image.*)?'],
         kev=r'linux\|kernel', high_only=True),
    # --- контейнеры
    dict(slug='docker', name='Docker Engine', cat='cont', cna=[r'docker\|docker (engine|desktop)', r'moby\|moby'], cpe=['docker:docker', 'docker:desktop', 'mobyproject:moby'],
         pkg=[r'docker(\.io|-ce)?', 'moby-engine'], osv={'Go': ['github.com/docker/docker', 'github.com/moby/moby']}, kev=r'docker\|.*'),
    dict(slug='containerd', name='containerd', cat='cont', cna=[r'containerd\|containerd'], cpe=['linuxfoundation:containerd'], pkg=[r'containerd(\.io)?'],
         osv={'Go': ['github.com/containerd/containerd', 'github.com/containerd/containerd/v2']}),
    dict(slug='runc', name='runc', cat='cont', cna=[r'opencontainers\|runc'], cpe=['linuxfoundation:runc'], pkg=['runc'], osv={'Go': ['github.com/opencontainers/runc']}, kev=r'.*\|runc'),
    dict(slug='kubernetes', name='Kubernetes', cat='cont', cna=[r'kubernetes\|(kubernetes|kubelet|kube-apiserver|kubectl)'], cpe=['kubernetes:kubernetes'],
         osv={'Go': ['k8s.io/kubernetes', 'k8s.io/apiserver']}, kev=r'kubernetes\|.*'),
    dict(slug='ingress-nginx', name='ingress-nginx', cat='cont', cna=[r'kubernetes\|ingress-nginx'], cpe=['kubernetes:ingress-nginx'], osv={'Go': ['k8s.io/ingress-nginx']}),
    # --- фреймворки и CMS
    dict(slug='laravel', name='Laravel', cat='fw', cna=[r'laravel\|(laravel|framework)'], cpe=['laravel:laravel', 'laravel:framework'],
         osv={'Packagist': ['laravel/framework', 'laravel/laravel']}, kev=r'laravel\|laravel framework'),
    dict(slug='symfony', name='Symfony', cat='fw', cna=[r'(sensiolabs|symfony)\|symfony'], cpe=['sensiolabs:symfony'],
         osv={'Packagist': ['symfony/symfony', 'symfony/http-foundation', 'symfony/http-kernel', 'symfony/security-http', 'symfony/framework-bundle',
                            'symfony/routing', 'symfony/process', 'symfony/security-core', 'symfony/twig-bridge', 'symfony/validator', 'symfony/mime']}),
    dict(slug='django', name='Django', cat='fw', cna=[r'(django|djangoproject)\|django'], cpe=['djangoproject:django'], pkg=[r'python3?-django'], osv={'PyPI': ['django']}),
    dict(slug='flask', name='Flask / Werkzeug', cat='fw', cna=[r'pallets\|(flask|werkzeug|jinja)'], cpe=['palletsprojects:flask', 'palletsprojects:werkzeug', 'palletsprojects:jinja'],
         osv={'PyPI': ['flask', 'werkzeug', 'jinja2']}),
    dict(slug='express', name='Express (Node.js)', cat='fw', cna=[r'expressjs\|express'], cpe=['expressjs:express', 'openjsf:express'], osv={'npm': ['express', 'body-parser', 'send', 'serve-static']}),
    dict(slug='nextjs', name='Next.js', cat='fw', cna=[r'vercel\|next\.?js'], cpe=['vercel:next.js'], osv={'npm': ['next']}, kev=r'vercel\|next\.?js'),
    dict(slug='wordpress', name='WordPress core', cat='fw', cna=[r'wordpress( foundation)?\|wordpress'], cpe=['wordpress:wordpress'], osv={'Packagist': ['johnpbloch/wordpress-core', 'roots/wordpress']}, kev=r'wordpress\|core'),
    dict(slug='drupal', name='Drupal core', cat='fw', cna=[r'drupal\|drupal( core)?'], cpe=['drupal:drupal'], osv={'Packagist': ['drupal/core', 'drupal/drupal']}, kev=r'drupal\|(drupal )?core'),
    dict(slug='joomla', name='Joomla! core', cat='fw', cna=[r'joomla!?( project)?\|joomla!?( cms| core)?'], cpe=['joomla:joomla!', 'joomla:joomla'], osv={'Packagist': ['joomla/joomla-cms']}, kev=r'joomla!?\|joomla!?'),
    dict(slug='rails', name='Ruby on Rails', cat='fw', cna=[r'rails\|rails', r'.*\|(ruby on rails|actionpack|activerecord|activestorage)'], cpe=['rubyonrails:rails'],
         osv={'RubyGems': ['rails', 'actionpack', 'activerecord', 'activesupport', 'activestorage', 'actionview', 'rack']}, kev=r'rails\|ruby on rails'),
    # --- обвязка
    dict(slug='phpmyadmin', name='phpMyAdmin', cat='tools', cna=[r'phpmyadmin\|phpmyadmin'], cpe=['phpmyadmin:phpmyadmin'], pkg=['phpmyadmin'], osv={'Packagist': ['phpmyadmin/phpmyadmin']}),
    dict(slug='composer', name='Composer', cat='tools', cna=[r'composer\|composer'], cpe=['getcomposer:composer'], osv={'Packagist': ['composer/composer']}),
    dict(slug='pip', name='pip / setuptools', cat='tools', cna=[r'(pypa|python packaging authority)\|(pip|setuptools)'], cpe=['pypa:pip', 'python:setuptools', 'python:pip'],
         osv={'PyPI': ['pip', 'setuptools']}),
    dict(slug='imagemagick', name='ImageMagick', cat='tools', cna=[r'imagemagick\|imagemagick'], cpe=['imagemagick:imagemagick'], pkg=[r'imagemagick(\d+)?'], kev=r'imagemagick\|imagemagick'),
    dict(slug='exim', name='Exim', cat='tools', cna=[r'exim\|exim'], cpe=['exim:exim'], pkg=[r'exim4?'], kev=r'exim\|.*'),
    dict(slug='postfix', name='Postfix', cat='tools', cna=[r'postfix\|postfix'], cpe=['postfix:postfix'], pkg=['postfix']),
    dict(slug='grafana', name='Grafana', cat='tools', cna=[r'grafana( labs)?\|grafana( oss| enterprise)?'], cpe=['grafana:grafana'], pkg=['grafana'], kev=r'grafana.*\|grafana'),
    dict(slug='jenkins', name='Jenkins core', cat='tools', cna=[r'jenkins( project)?\|jenkins'], cpe=['jenkins:jenkins'], pkg=['jenkins'], kev=r'jenkins\|jenkins.*'),
    dict(slug='gitlab', name='GitLab', cat='tools', cna=[r'gitlab\|gitlab'], cpe=['gitlab:gitlab'], kev=r'gitlab\|.*'),
]

BY_SLUG = {p['slug']: p for p in P}


def _rx(pats):
    return [re.compile(p, re.I) for p in pats]


for p in P:
    p['_cna'] = _rx(p.get('cna', []))
    p['_pkg'] = _rx(p.get('pkg', []))
    p['_kev'] = re.compile(p['kev'], re.I) if p.get('kev') else None
    p['_cpe'] = {c.lower() for c in p.get('cpe', [])}
    p.setdefault('osv', {})

OSV_INDEX = {}  # (ecosystem, name.lower()) -> slug
for p in P:
    for eco, names in p['osv'].items():
        for n in names:
            OSV_INDEX[(eco, n.lower())] = p['slug']
OSV_ECOS = sorted({e for e, _ in OSV_INDEX})


def cpe_key(cpe):
    """'cpe:2.3:a:f5:nginx:*:...' -> 'f5:nginx'."""
    s = cpe.split(':')
    return f'{s[3]}:{s[4]}'.lower() if len(s) > 4 else ''


def match_affected(vendor='', product='', package='', cpes=(), ecosystem='', osv_name=''):
    """-> множество slug каталога, к которым относится запись affected."""
    hit = set()
    vp = f'{(vendor or "").strip()}|{(product or "").strip()}'
    pk = (package or '').strip()
    ck = {cpe_key(c) for c in cpes or ()}
    if ecosystem and osv_name:
        s = OSV_INDEX.get((ecosystem.split(':')[0], osv_name.lower()))
        if s:
            hit.add(s)
    for p in P:
        if any(r.fullmatch(vp) for r in p['_cna']):
            hit.add(p['slug'])
        elif pk and any(r.fullmatch(pk) for r in p['_pkg']):
            hit.add(p['slug'])
        elif ck & p['_cpe']:
            hit.add(p['slug'])
    return hit


def match_kev(vendor, product):
    vp = f'{vendor}|{product}'
    return {p['slug'] for p in P if p['_kev'] and p['_kev'].fullmatch(vp)}
