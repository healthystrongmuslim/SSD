package edu.nu.owaspapivulnlab;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.Base64;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class AdditionalSecurityExpectationsTests {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper om;

    String login(String user, String pw) throws Exception {
        String res = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\""+user+"\",\"password\":\""+pw+"\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        JsonNode n = om.readTree(res);
        return n.get("token").asText();
    }

    @Test
    void protected_endpoints_require_authentication() throws Exception {
        // Expectation in fixed app: /api/users requires auth -> 401
        mvc.perform(get("/api/users"))
                .andExpect(status().isUnauthorized()); // Fails now due to permitAll on GET
    }

    @Test
    void delete_user_requires_admin() throws Exception {
        String tUser = login("alice","alice123"); // not admin
        mvc.perform(delete("/api/users/1").header("Authorization","Bearer "+tUser))
                .andExpect(status().isForbidden()); // Fails now
    }

    @Test
    void create_user_does_not_allow_role_escalation() throws Exception {
        // In fixed app, server should ignore role/isAdmin from payload & return 201
        String payload = "{\"username\":\"eve2\",\"password\":\"pw\",\"email\":\"e2@e\",\"role\":\"ADMIN\",\"isAdmin\":true}";
        mvc.perform(post("/api/users").contentType(MediaType.APPLICATION_JSON).content(payload))
                .andExpect(status().isCreated()) // Fails now (200 OK)
                .andExpect(jsonPath("$.role", anyOf(nullValue(), is("USER")))) // Fails now (ADMIN)
                .andExpect(jsonPath("$.isAdmin", anyOf(nullValue(), is(false)))); // Fails now (true)
    }

    @Test
    void jwt_must_be_valid_and_aud_iss_checked() throws Exception {
    String strong = login("alice","alice123");

    mvc.perform(get("/api/accounts").header("Authorization", "Bearer " + strong))
        .andExpect(status().isOk());

    String[] parts = strong.split("\\.");
    ObjectNode tamperedClaims = (ObjectNode) om.readTree(Base64.getUrlDecoder().decode(parts[1]));
    tamperedClaims.put("iss", "attacker");
    String tamperedPayload = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(om.writeValueAsBytes(tamperedClaims));
    String forged = parts[0] + "." + tamperedPayload + "." + parts[2];

    mvc.perform(get("/api/accounts").header("Authorization", "Bearer " + forged))
        .andExpect(status().isUnauthorized());
    }

    @Test
    void account_owner_only_access() throws Exception {
        String alice = login("alice","alice123");
        // In fixed code this should be forbidden
        mvc.perform(get("/api/accounts/2/balance").header("Authorization","Bearer "+alice))
                .andExpect(status().isForbidden()); // Fails now
    }
}
