package uk.gov.defra.tracesx.common.security.conversation.id;


import org.springframework.beans.factory.annotation.Autowired;

import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

public class ConversationFilter implements Filter {

  private static final String CONVERSATION_ID_HEADER = "INS-ConversationId";

  private final ConversationStore conversationStore;

  @Autowired
  public ConversationFilter(ConversationStore conversationStore) {
    this.conversationStore = conversationStore;
  }

  @Override
  public void doFilter(
      ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
      throws IOException, ServletException {

    HttpServletRequest request = (HttpServletRequest) servletRequest;
    String conversationId = request.getHeader(CONVERSATION_ID_HEADER);

    try {
      conversationStore.setConversationId(conversationId);
      chain.doFilter(servletRequest, servletResponse);
    } finally {
      // Clear the thread in case filter is skipped
      conversationStore.clear();
    }
  }
}
