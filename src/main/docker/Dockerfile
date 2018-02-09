FROM openjdk:8-jre-alpine

RUN mkdir maven && mkdir maven/config
COPY maven/ /maven/
COPY /artifact_runner.sh maven/
COPY /logback.xml maven/config/

EXPOSE ${project.service.port}

CMD /maven/artifact_runner.sh /maven/${final-artifact-name}.jar
