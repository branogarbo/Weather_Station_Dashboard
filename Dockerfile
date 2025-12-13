FROM python:3-slim

EXPOSE 3000

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN python -m venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

COPY requirements.txt .
RUN python -m pip install -r requirements.txt

COPY . /app

RUN adduser -u 5678 --disabled-password --gecos "" appuser && chown -R appuser /app
USER appuser

WORKDIR /app

CMD ["gunicorn", "--bind", "0.0.0.0:3000", "app:app"]
