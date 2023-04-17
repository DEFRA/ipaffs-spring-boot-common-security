package uk.gov.defra.tracesx.common.security.conversation.id;

import java.io.IOException;
import java.util.Optional;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;

public class ConversationFilter implements Filter {

  private static final String CONVERSATION_ID_HEADER = "INS-ConversationId";
  private static final String CONVERSATION_IP_HEADER = "INS-ConversationIp";
  private static final String DEFAULT_CONVERSATION_IP = "0.0.0.0";

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
    Optional<String> conversationIp =
        Optional.ofNullable(request.getHeader(CONVERSATION_IP_HEADER))
            .map(header -> header.split(":")[0]);
    try {
      conversationStore.setConversationId(conversationId);
      conversationStore.setConversationIp(conversationIp.orElse(DEFAULT_CONVERSATION_IP));
      chain.doFilter(servletRequest, servletResponse);
    } finally {
      // Clear the thread in case filter is skipped
      conversationStore.clear();
    }
  }
}
