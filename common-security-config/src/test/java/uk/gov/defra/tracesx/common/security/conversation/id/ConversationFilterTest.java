package uk.gov.defra.tracesx.common.security.conversation.id;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.UUID;
import javax.servlet.FilterChain;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

@RunWith(MockitoJUnitRunner.class)
public class ConversationFilterTest {

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

  @Before
  public void before() {
    conversationFilter = new ConversationFilter(conversationStore);
  }

  @Test
  public void doFilter_withCorrectHeader_setsConversationId() throws Exception {
    when(servletRequest.getHeader("INS-ConversationId")).thenReturn(CONVERSATION_ID);
    when(servletRequest.getHeader("INS-ConversationIp")).thenReturn(CONVERSATION_IP_HEADER);
    conversationFilter.doFilter(servletRequest, servletResponse, filterChain);

    verify(conversationStore, times(1)).setConversationId(CONVERSATION_ID);
    verify(conversationStore, times(1)).clear();
  }

  @Test
  public void doFilter_withCorrectHeader_setsConversationIp() throws Exception {
    when(servletRequest.getHeader("INS-ConversationIp")).thenReturn(CONVERSATION_IP_HEADER);
    conversationFilter.doFilter(servletRequest, servletResponse, filterChain);

    verify(conversationStore, times(1)).setConversationIp(CONVERSATION_IP);
    verify(conversationStore, times(1)).clear();
  }

  @Test
  public void doFilter_withNoConversationIpHeader_doesNotThrowException() {
    when(servletRequest.getHeader("INS-ConversationIp")).thenReturn(null);

    assertThatCode(() -> conversationFilter.doFilter(servletRequest, servletResponse, filterChain)).doesNotThrowAnyException();
    verify(conversationStore, times(1)).setConversationIp(DEFAULT_CONVERSATION_IP);
  }
}
