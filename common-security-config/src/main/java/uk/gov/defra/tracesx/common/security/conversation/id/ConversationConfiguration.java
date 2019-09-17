package uk.gov.defra.tracesx.common.security.conversation.id;

import org.springframework.aop.framework.ProxyFactoryBean;
import org.springframework.aop.target.ThreadLocalTargetSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Scope;

@Configuration
public class ConversationConfiguration {

  @Bean(destroyMethod = "destroy")
  public ThreadLocalTargetSource threadLocalConversationStore() {
    ThreadLocalTargetSource result = new ThreadLocalTargetSource();
    result.setTargetBeanName("conversationStore");
    return result;
  }

  @Primary
  @Bean
  public ProxyFactoryBean proxiedThreadLocalTargetSource(
      ThreadLocalTargetSource threadLocalTargetSource) {
    ProxyFactoryBean result = new ProxyFactoryBean();
    result.setTargetSource(threadLocalTargetSource);
    return result;
  }

  @Bean(name = "conversationStore")
  @Scope(scopeName = "prototype")
  public ConversationStore conversationStore() {
    return new ConversationStore();
  }
}
