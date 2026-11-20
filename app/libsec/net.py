import httpx

UA = 'libsec-tracker/0.1 (+https://libsec.alid.in)'


def client(timeout=60):
    return httpx.Client(headers={'User-Agent': UA}, timeout=timeout, follow_redirects=True, http2=False)


def cond_get(cl, url, state, key=None):
    """GET с If-None-Match / If-Modified-Since. state — dict курсора источника. -> response или None (не изменилось)."""
    key = key or url
    meta = state.setdefault('http', {}).get(key, {})
    hdr = {}
    if meta.get('etag'):
        hdr['If-None-Match'] = meta['etag']
    if meta.get('lm'):
        hdr['If-Modified-Since'] = meta['lm']
    r = cl.get(url, headers=hdr)
    if r.status_code == 304:
        return None
    r.raise_for_status()
    state['http'][key] = {'etag': r.headers.get('etag'), 'lm': r.headers.get('last-modified')}
    return r
