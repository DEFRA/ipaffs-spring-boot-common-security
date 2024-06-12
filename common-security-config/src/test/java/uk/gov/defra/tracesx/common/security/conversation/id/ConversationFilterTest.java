package uk.gov.defra.tracesx.common.security.conversation.id;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ConversationFilterTest {

  private static final String CONVERSATION_ID = UUID.randomUUID().toString();
  private static final String CONVERSATION_IP_HEADER = "1.1.1.1:1111";
  private static final String CONVERSATION_IP = "1.1.1.1";
  private static final String DEFAULT_CONVERSATION_IP = "0.0.0.0";

  @Mock
  private ConversationStore conversationStore;

  @Mock
  private HttpServletRequest servletRequest;

  @Mock
  private ServletResponse servletResponse;

  @Mock
  private FilterChain filterChain;

  private ConversationFilter conversationFilter;

  @BeforeEach
  public void before() {
    conversationFilter = new ConversationFilter(conversationStore);
  }

  @Test
  void doFilter_withCorrectHeader_setsConversationId() throws Exception {
    when(servletRequest.getHeader("INS-ConversationId")).thenReturn(CONVERSATION_ID);
    when(servletRequest.getHeader("INS-ConversationIp")).thenReturn(CONVERSATION_IP_HEADER);
    conversationFilter.doFilter(servletRequest, servletResponse, filterChain);

    verify(conversationStore, times(1)).setConversationId(CONVERSATION_ID);
    verify(conversationStore, times(1)).clear();
  }

  @Test
  void doFilter_withCorrectHeader_setsConversationIp() throws Exception {
    when(servletRequest.getHeader("INS-ConversationId")).thenReturn(CONVERSATION_ID);
    when(servletRequest.getHeader("INS-ConversationIp")).thenReturn(CONVERSATION_IP_HEADER);
    conversationFilter.doFilter(servletRequest, servletResponse, filterChain);

    verify(conversationStore, times(1)).setConversationIp(CONVERSATION_IP);
    verify(conversationStore, times(1)).clear();
  }

  @Test
  void doFilter_withNoConversationIpHeader_doesNotThrowException() {
    when(servletRequest.getHeader("INS-ConversationId")).thenReturn(CONVERSATION_ID);

    assertThatCode(() -> conversationFilter.doFilter(servletRequest, servletResponse,
        filterChain)).doesNotThrowAnyException();
    verify(conversationStore, times(1)).setConversationIp(DEFAULT_CONVERSATION_IP);
  }
}
