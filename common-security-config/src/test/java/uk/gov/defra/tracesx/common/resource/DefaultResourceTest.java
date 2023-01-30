package uk.gov.defra.tracesx.common.resource;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

public class DefaultResourceTest {

  @Test
  public void defaultResource_ReturnsHttpStatusOK() {
    DefaultResource defaultResource = new DefaultResource();
    ResponseEntity responseEntity = defaultResource.defaultGet();

    assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
  }
}
