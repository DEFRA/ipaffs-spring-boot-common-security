package uk.gov.defra.tracesx.common;

import static org.junit.Assert.assertTrue;

import org.junit.Test;
import uk.gov.defra.tracesx.common.security.IdTokenUserDetails;

public class IdTokenUserDetailsTest {

  @Test
  public void idTokenUserDetails_DefaultMethodsShouldReturnTrue() {
    IdTokenUserDetails idTokenUserDetails = IdTokenUserDetails.builder().build();

    assertTrue(idTokenUserDetails.isAccountNonExpired());
    assertTrue(idTokenUserDetails.isAccountNonLocked());
    assertTrue(idTokenUserDetails.isCredentialsNonExpired());
    assertTrue(idTokenUserDetails.isEnabled());
  }
}
