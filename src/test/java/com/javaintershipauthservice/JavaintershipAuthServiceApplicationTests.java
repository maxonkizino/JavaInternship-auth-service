package com.javaintershipauthservice;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.annotation.DirtiesContext;

@SpringBootTest
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class JavaintershipAuthServiceApplicationTests extends PostgresIntegrationTestBase {

    @Test
    void contextLoads() {
    }

}
