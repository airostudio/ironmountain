/** Frequently-downloaded packages used as typosquatting anchors. */
export const POPULAR_NPM = [
  "react", "react-dom", "next", "vue", "angular", "svelte", "express", "koa", "fastify", "hapi", "nestjs",
  "lodash", "underscore", "ramda", "axios", "node-fetch", "got", "request", "superagent", "undici",
  "moment", "dayjs", "date-fns", "luxon", "uuid", "nanoid", "chalk", "commander", "yargs", "minimist",
  "debug", "dotenv", "cross-env", "rimraf", "mkdirp", "glob", "fs-extra", "chokidar", "semver",
  "typescript", "ts-node", "tsx", "esbuild", "webpack", "rollup", "vite", "parcel", "babel-core",
  "eslint", "prettier", "jest", "mocha", "chai", "vitest", "sinon", "cypress", "playwright", "puppeteer",
  "mongoose", "mongodb", "mysql", "mysql2", "pg", "sqlite3", "redis", "ioredis", "sequelize", "prisma",
  "typeorm", "knex", "graphql", "apollo-server", "socket.io", "ws", "jsonwebtoken", "bcrypt", "bcryptjs",
  "passport", "helmet", "cors", "body-parser", "cookie-parser", "express-session", "multer", "morgan",
  "winston", "pino", "bunyan", "nodemailer", "sharp", "jimp", "cheerio", "jsdom", "marked", "highlight.js",
  "zod", "yup", "joi", "ajv", "class-validator", "rxjs", "immer", "redux", "mobx", "zustand",
  "tailwindcss", "postcss", "autoprefixer", "sass", "less", "styled-components", "classnames", "clsx",
  "electron", "react-router", "react-router-dom", "jquery", "bootstrap", "three", "d3", "chart.js",
  "openai", "@anthropic-ai/sdk", "langchain", "ethers", "web3", "stripe", "aws-sdk", "firebase",
  "colors", "inquirer", "ora", "execa", "shelljs", "node-sass", "coffee-script", "event-stream",
  "ua-parser-js", "coa", "rc", "eslint-scope", "electron-builder", "nodemon", "pm2", "concurrently",
];

export const POPULAR_PYPI = [
  "requests", "urllib3", "numpy", "pandas", "scipy", "matplotlib", "seaborn", "scikit-learn", "tensorflow",
  "torch", "keras", "transformers", "flask", "django", "fastapi", "uvicorn", "gunicorn", "starlette",
  "pydantic", "sqlalchemy", "psycopg2", "psycopg2-binary", "pymysql", "redis", "celery", "boto3",
  "botocore", "awscli", "google-cloud-storage", "pyyaml", "toml", "jinja2", "click", "typer", "rich",
  "pytest", "tox", "black", "flake8", "pylint", "mypy", "isort", "setuptools", "wheel", "pip",
  "cryptography", "pycryptodome", "pyjwt", "bcrypt", "paramiko", "beautifulsoup4", "lxml", "selenium",
  "scrapy", "httpx", "aiohttp", "openai", "anthropic", "langchain", "pillow", "opencv-python",
  "python-dateutil", "pytz", "six", "attrs", "colorama", "tqdm", "python-dotenv", "certifi", "idna",
  "charset-normalizer", "simplejson", "ujson", "orjson", "pymongo", "elasticsearch", "kafka-python",
  "docker", "kubernetes", "ansible", "fabric", "invoke", "jupyter", "notebook", "ipython", "networkx",
  "sympy", "nltk", "spacy", "gensim", "xgboost", "lightgbm", "catboost", "statsmodels", "plotly",
];

/** Package names known to have been used in malware / typosquatting campaigns. */
export const KNOWN_MALICIOUS_NPM = new Set([
  // 2017 crossenv campaign and later incidents
  "crossenv", "cross-env.js", "d3.js", "fabric-js", "ffmepg", "gruntcli", "http-proxy.js", "jquery.js",
  "mongose", "mssql.js", "mssql-node", "mysqljs", "nodecaffe", "nodefabric", "node-fabric",
  "nodeffmpeg", "nodemailer-js", "nodemailer.js", "nodemssql", "node-opencv", "node-opensl", "node-openssl",
  "noderequest", "nodesass", "nodesqlite", "node-sqlite", "node-tkinter", "opencv.js", "openssl.js",
  "proxy.js", "shadowsock", "sqlite.js", "sqliter", "discord.dll", "electorn", "loadyaml", "lodashs",
  "babelcli", "flatmap-stream",
]);

export const KNOWN_MALICIOUS_PYPI = new Set([
  // 2017 SK-CSIRT report and later campaigns
  "colourama", "djanga", "python-sqlite", "urlib3", "urllib", "acqusition", "apidev-coop", "bzip", "crypt",
  "django-server", "pwd", "setup-tools", "telnet", "python-mysql", "python-ftp", "jeilyfish", "python3-dateutil",
  "requesst", "reqeusts",
]);
