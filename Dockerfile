FROM registry.access.redhat.com/ubi8/ubi-minimal as unzipper

ENV SUBFINDER_VERSION=2.5.5
ENV AMASS_VERSION=3.21.2

RUN microdnf install curl tar zip

RUN curl -L --output /opt/subfinder.zip https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip
RUN unzip /opt/subfinder.zip -d /usr/local/bin/

RUN curl -L --output /opt/amass.zip https://github.com/OWASP/Amass/releases/download/v${AMASS_VERSION}/amass_linux_amd64.zip
RUN unzip -j /opt/amass.zip -d /usr/local/bin/

FROM registry.access.redhat.com/ubi8/python-39:1-97

USER 0
ADD . .

COPY --from=unzipper /usr/local/bin/subfinder /usr/local/bin/
COPY --from=unzipper /usr/local/bin/amass /usr/local/bin/

# Install the dependencies
RUN pip install --upgrade pip && \
    pip install -r requirements.txt && \
    python manage.py collectstatic --noinput && \
    python manage.py migrate && \
    chown 1001:0 /opt/app-root/src/StartScan/FILES # TODO: change to a generic place (ex: /tmp/...)

USER 1001

# Run the application
CMD python -m gunicorn project.wsgi:application --bind 0.0.0.0:8000 --workers 5
