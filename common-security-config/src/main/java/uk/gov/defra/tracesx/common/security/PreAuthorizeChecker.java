package uk.gov.defra.tracesx.common.security;

import static org.springframework.core.annotation.AnnotationUtils.findAnnotation;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

public class PreAuthorizeChecker implements HandlerInterceptor {

  private static final String MESSAGE = "Rights are not defined for this handler";

  @Override
  public boolean preHandle(
      HttpServletRequest request, HttpServletResponse response, Object handler) {
    if (handler instanceof HandlerMethod) {
      HandlerMethod hm = (HandlerMethod) handler;
      PreAuthorize annotation = findAnnotation(hm.getMethod(), PreAuthorize.class);
      if (annotation == null) {
        // prevent access to method without security restrictions
        throw new NullPointerException(MESSAGE);
      }
    }
    return true;
  }
}
