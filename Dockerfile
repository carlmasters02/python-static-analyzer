# --- Base image ---------------------------------------------------------
# Start from an official Python image. The "-slim" variant is Debian with
# the non-essential packages stripped out. Smaller image = faster to pull
# AND a smaller "attack surface" (fewer programs a hacker could exploit).
FROM python:3.13-slim

# --- Create a non-root user --------------------------------------------
# By default a container runs everything as "root" (full admin). If an
# attacker ever broke out of our app, they'd inherit those powers. We make
# an ordinary user now and switch to it below, so the app runs unprivileged.
RUN useradd --create-home appuser

# All following commands run inside /app.
WORKDIR /app

# --- Install the app ----------------------------------------------------
# Copy only the files needed to install the package. (We copy these before
# the rest so Docker can cache the install layer and rebuild faster.)
COPY pyproject.toml README.md ./
COPY src ./src

# Install our package. --no-cache-dir keeps the image smaller by not
# storing pip's download cache inside it.
RUN pip install --no-cache-dir --root-user-action=ignore .

# --- Drop privileges ----------------------------------------------------
# Everything from here on runs as the unprivileged "appuser", not root.
USER appuser

# --- Run ----------------------------------------------------------------
# ENTRYPOINT is the command that always runs; CMD supplies default
# arguments you can override:
#   docker run --rm hello-cli               -> hello --name World
#   docker run --rm hello-cli --name Ada    -> hello --name Ada
ENTRYPOINT ["hello"]
CMD ["--name", "World"]
