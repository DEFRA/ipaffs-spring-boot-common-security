package uk.gov.defra.tracesx.common.security.conversation.id;

import static org.junit.Assert.assertNull;

import org.junit.jupiter.api.Test;

class ConversationStoreTest {

  @Test
  void clear_SetsValuesNull() {
    ConversationStore conversationStore = new ConversationStore("id", "ip");
    conversationStore.clear();

    assertNull(conversationStore.getConversationId());
    assertNull(conversationStore.getConversationIp());
  }
}
