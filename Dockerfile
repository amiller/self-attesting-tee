FROM python:3.12-slim
WORKDIR /app
RUN pip install flask httpx dstack-sdk anthropic
COPY . .
ARG GIT_REPO=https://github.com/amiller/self-attesting-tee
ARG GIT_COMMIT=unknown
RUN echo "{\"repo\": \"${GIT_REPO}\", \"commit\": \"${GIT_COMMIT}\"}" > /app/git_info.json
CMD ["python", "app.py"]
