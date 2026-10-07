import gc

apps = [o for o in gc.get_objects() if type(o).__name__ == "FastAPI"]
out = []
for a in apps:
    routes = getattr(getattr(a, "router", None), "routes", [])
    paths = [getattr(r, "path", "?") for r in routes]
    out.append(str(id(a)) + ":" + ",".join(paths[:15]))
_out = "|".join(out)
