- Generate a local cache with all dependencies instead of installing everything system wide
```
$ python3 -m venv .venv
$ . .venv/bin/activate
$ pip install "mkdocs-material[all]"
```

- Build MkDocs website content
```
$ mkdocs build
```

- Debug and edit current modif, pointing your browser to http://localhost:8000/
```
$ mkdocs serve
```

- deactivate chrooted venv
```
$ deactivate
```
