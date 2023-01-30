package uk.gov.defra.tracesx.common.security.conversation.id;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.aop.framework.ProxyFactoryBean;
import org.springframework.aop.target.ThreadLocalTargetSource;

@RunWith(MockitoJUnitRunner.class)
public class ConversationConfigurationTest {

  @Mock
  private ThreadLocalTargetSource threadLocalTargetSource;

  private ConversationConfiguration conversationConfiguration;

  @Before
  public void setUp() {
    conversationConfiguration = new ConversationConfiguration();
  }

  @Test
  public void threadLocalConversationStore_ReturnsCorrectTargetSource() {
    ThreadLocalTargetSource result = conversationConfiguration.threadLocalConversationStore();

    assertEquals("conversationStore", result.getTargetBeanName());
  }

  @Test
  public void proxiedThreadLocalTargetSource_ReturnsCorrectProxyFactoryBean() {
    ProxyFactoryBean result = conversationConfiguration.proxiedThreadLocalTargetSource(threadLocalTargetSource);

    assertEquals(threadLocalTargetSource, result.getTargetSource());
  }

  @Test
  public void conversationStore_ReturnsNewConversationStore() {
    ConversationStore result = conversationConfiguration.conversationStore();

    assertThat(result, instanceOf(ConversationStore.class));
  }
}
