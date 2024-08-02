package uk.gov.defra.tracesx.common.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.method.HandlerMethod;

class PreAuthorizeCheckerTest {

  private static final String PRE_AUTHORIZE_CHECKER_METHOD = "preAuthorizeCheckerMethod";
  private static final String PRE_AUTHORIZE_CHECKER_METHOD_WITH_ANNOTATION = "preAuthorizeCheckerMethodWithAnnotation";

  private final HttpServletRequest requestMock = mock();
  private final HttpServletResponse responseMock = mock();

  private final PreAuthorizeChecker testee = new PreAuthorizeChecker();

  public void preAuthorizeCheckerMethod() {

  }
  @PreAuthorize("hasAuthority('economicoperator.read')")
  public void preAuthorizeCheckerMethodWithAnnotation() {

  }

  @Test
  void whenPreAuthorizeIsNotDefinedThenThrowError() throws Exception {
    HandlerMethod handlerMethod = new HandlerMethod(this, this.getClass().getMethod(
        PRE_AUTHORIZE_CHECKER_METHOD));
    RuntimeException runtimeException = Assertions.assertThrows(RuntimeException.class, () -> {
      testee.preHandle(requestMock, responseMock, handlerMethod);
    });

    Assertions.assertEquals("Rights are not defined for this handler", runtimeException.getMessage());
  }

  @Test
  void whenPreAuthorizeIsDefinedThenReturnTrue() throws Exception {

    HandlerMethod handlerMethod = new HandlerMethod(this, this.getClass().getMethod(
        PRE_AUTHORIZE_CHECKER_METHOD_WITH_ANNOTATION));
    assertThat(testee.preHandle(requestMock, responseMock, handlerMethod)).isTrue();
  }
}
