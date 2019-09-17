package uk.gov.defra.tracesx.common.security.conversation.id;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor(access = AccessLevel.PUBLIC)
@AllArgsConstructor(access = AccessLevel.PUBLIC)
public class ConversationStore {

  private String conversationId;

  public void clear() {
    this.conversationId = null;
  }
}
