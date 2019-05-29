package uk.gov.defra.tracesx.common.security;

import lombok.Builder;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;

/**
 * Identity roles are string of individual role ids.
 */
@Data
@Builder
public class OrganisationGrantedAuthority implements GrantedAuthority {

  public OrganisationGrantedAuthority(String authority) {
    this.authority = authority;
  }

  private String authority;

}
