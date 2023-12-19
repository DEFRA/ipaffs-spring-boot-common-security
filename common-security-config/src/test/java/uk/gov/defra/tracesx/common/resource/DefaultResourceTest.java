package uk.gov.defra.tracesx.common.resource;

import static org.junit.Assert.assertEquals;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

class DefaultResourceTest {

  @Test
  void defaultResource_ReturnsHttpStatusOK() {
    DefaultResource defaultResource = new DefaultResource();
    ResponseEntity responseEntity = defaultResource.defaultGet();

    assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
  }
}
