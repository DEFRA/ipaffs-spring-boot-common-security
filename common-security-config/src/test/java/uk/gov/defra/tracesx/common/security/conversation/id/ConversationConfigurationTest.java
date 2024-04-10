package uk.gov.defra.tracesx.common.security.conversation.id;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.aop.framework.ProxyFactoryBean;
import org.springframework.aop.target.ThreadLocalTargetSource;

@ExtendWith(MockitoExtension.class)
class ConversationConfigurationTest {

  @Mock
  private ThreadLocalTargetSource threadLocalTargetSource;

  private ConversationConfiguration conversationConfiguration;

  @BeforeEach
  public void setUp() {
    conversationConfiguration = new ConversationConfiguration();
  }

  @Test
  void threadLocalConversationStore_ReturnsCorrectTargetSource() {
    ThreadLocalTargetSource result = conversationConfiguration.threadLocalConversationStore();

    assertThat(result.getTargetBeanName()).isEqualTo("conversationStore");
  }

  @Test
  void proxiedThreadLocalTargetSource_ReturnsCorrectProxyFactoryBean() {
    ProxyFactoryBean result = conversationConfiguration.proxiedThreadLocalTargetSource(
        threadLocalTargetSource);

    assertThat(result.getTargetSource()).isEqualTo(threadLocalTargetSource);
  }

  @Test
  void conversationStore_ReturnsNewConversationStore() {
    ConversationStore result = conversationConfiguration.conversationStore();

    assertThat(result).isInstanceOf(ConversationStore.class);
  }
}
