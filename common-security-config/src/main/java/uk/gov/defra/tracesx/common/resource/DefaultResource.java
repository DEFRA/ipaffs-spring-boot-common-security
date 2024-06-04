package uk.gov.defra.tracesx.common.resource;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
public class DefaultResource {

  // The purpose of this class is to prevent spurious logging of exceptions when deployed to Azure
  @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<Void> defaultGet() {
    return ResponseEntity.ok().build();
  }
}
