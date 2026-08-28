# Adaptive Zero-Trust Access Control — app image
FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 5001
ENV HOST=0.0.0.0
# start_up() creates tables and loads (or trains) the model, then serves
CMD ["python", "app.py"]
