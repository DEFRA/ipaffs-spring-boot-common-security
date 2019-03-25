package uk.gov.defra.tracesx.common.security;

import lombok.Builder;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;

/**
 * Identity roles are formatted organisation:role:status
 */
@Data
@Builder
public class OrganisationGrantedAuthority implements GrantedAuthority {

  private String authority;
  private String organisation;
  private String status;

}
