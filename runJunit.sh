#!/bin/sh
export JAVA_HOME=$JAVA_HOME_11
mvn clean test jacoco:report -f pom.xml -Dmaven.repo.local=${WORKSPACE}/.m2
