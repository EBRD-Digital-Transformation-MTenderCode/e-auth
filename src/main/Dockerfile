FROM openjdk:8-jre-alpine

RUN mkdir maven && mkdir maven/config
COPY maven/ /maven/
COPY /scripts/artifact_runner.sh maven/
COPY /resources/logback.xml maven/config/

EXPOSE ${project.service.port}

CMD /maven/artifact_runner.sh /maven/${final-artifact-name}.jar
