package uk.gov.defra.tracesx.common.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.MockitoAnnotations.initMocks;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.method.HandlerMethod;

class PreAuthorizeCheckerTest {

  private static final String PRE_AUTHORIZE_CHECKER_METHOD = "preAuthorizeCheckerMethod";
  private static final String PRE_AUTHORIZE_CHECKER_METHOD_WITH_ANNOTATION = "preAuthorizeCheckerMethodWithAnnotation";

  @Mock
  private HttpServletRequest requestMock;
  @Mock
  private HttpServletResponse responseMock;

  @InjectMocks
  PreAuthorizeChecker testee;

  @BeforeEach
  public void setUp() {
    initMocks(this);
  }

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
