package uk.gov.defra.tracesx.common.security.conversation.id;

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
    conversationFilter.doFilter(servletRequest, servletResponse, filterChain);

    verify(conversationStore, times(1)).setConversationId(CONVERSATION_ID);
    verify(conversationStore, times(1)).clear();
  }
}
