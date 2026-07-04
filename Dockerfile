FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git nmap \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir sqlmap \
 && useradd --create-home --uid 10001 app \
 && mkdir -p /app /runs \
 && chown -R app:app /app /runs

COPY docker-assets/manifest.tsv /tmp/pd/manifest.tsv
RUN set -eux; \
    cd /tmp/pd; \
    while IFS='	' read -r name version url sha; do \
      curl -fsSL "$url" -o "$name.zip"; \
      echo "$sha  $name.zip" | sha256sum -c -; \
      python3 -c "import sys,zipfile; name,src,dst=sys.argv[1:]; open(dst,'wb').write(zipfile.ZipFile(src).read(name))" "$name" "$name.zip" "/usr/local/bin/$name"; \
      chmod +x "/usr/local/bin/$name"; \
    done < manifest.tsv; \
    rm -rf /tmp/pd

WORKDIR /app
COPY --chown=app:app autoattack_agent.py /app/autoattack_agent.py
USER app
VOLUME ["/runs"]
ENTRYPOINT ["python3", "/app/autoattack_agent.py"]
