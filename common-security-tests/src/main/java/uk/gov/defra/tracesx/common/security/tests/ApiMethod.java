package uk.gov.defra.tracesx.common.security.tests;

import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

@FunctionalInterface
public interface ApiMethod {
  Response call(RequestSpecification requestSpecification);
}
