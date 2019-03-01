# Common Security Tests

This module provides abstract / stub test classes and helper classes for writing integration tests
that verify the security configuration of a service.

Each service that uses `common-security-config` should implement the following tests:

## AbstractApiAuthenticationTest

Extend this class and declare a static `@DataPoints` field named `AbstractApiAuthenticationTest.DATA_POINTS_NAME`
that is an array of lambda which consume a `RequestSpecification` and produce a `Response`. The 
`RequestSpecification` provided to the lambda will already contain the
security headers required for the test. The lambda should provide any further parameters and call
the appropriate method to complete the request e.g. `RequestSpecification#get()` or 
`RequestSpecification#post()`. There should be a lambda for every API exposed by the service so
the security of each endpoint can be verified.
   
The subclass needs to be annotated `@RunWith(Theories.class)`.

Example implementation:

    @RunWith(Theories.class)
    public class TestApiAuthentication extends AbstractApiAuthenticationTest {
    
      private static final CountriesServiceHelper helper = new CountriesServiceHelper();
    
      @DataPoints("API Methods")
      public static ApiMethod[] getApiMethods() {
        return new ApiMethod[]{
            spec -> spec.get(helper.getAllCountries()),
            spec -> spec.get(helper.getNonUKCountries()),
            spec -> spec.get(helper.getCountryById("MY")),
            spec -> spec.post(helper.postCountries()),
            spec -> spec.delete(helper.deleteCountries("AB"))
        };
      }
    }

## AbstractAdminAuthenticationTest

Just implement `getAdminUrl()` to return the full URL of the `/admin` endpoint.

Example implementation:

    public class TestAdminAuthentication extends AbstractAdminAuthenticationTest {
    
      private static final CountriesServiceHelper helper = new CountriesServiceHelper();
    
      @Override
      protected String getAdminUrl() {
        return helper.getUrl("/admin");
      }
    }