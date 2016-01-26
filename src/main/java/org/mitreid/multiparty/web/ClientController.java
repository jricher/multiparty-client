/*******************************************************************************
 * Copyright 2015 The MITRE Corporation
 *   and the MIT Internet Trust Consortium
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package org.mitreid.multiparty.web;

import java.io.IOException;
import java.security.Principal;
import java.util.List;
import java.util.Locale;
import java.util.Spliterator;
import java.util.UUID;

import javax.servlet.http.HttpSession;

import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.mitre.oauth2.model.RegisteredClient;
import org.mitre.openid.connect.client.service.ClientConfigurationService;
import org.mitreid.multiparty.model.MultipartyServerConfiguration;
import org.mitreid.multiparty.service.AccessTokenService;
import org.mitreid.multiparty.service.MultipartyServerConfigurationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MimeTypeUtils;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.Iterators;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Handles requests for the application home page.
 */
@Controller
public class ClientController {

	/**
	 * 
	 */
	private static final String AUTHSERVERURI_SESSION_VAR = "AUTHSERVERURI";

	/**
	 * 
	 */
	private static final String RESOURCE_SESSION_VAR = "RESOURCE";

	/**
	 * 
	 */
	private static final String STATE_SESSION_VAR = "STATE";

	/**
	 * 
	 */
	private static final String TICKET_SESSION_VAR = "TICKET";

	private static final Logger logger = LoggerFactory.getLogger(ClientController.class);

	@Autowired
	private ClientConfigurationService clientConfig;
	
	@Autowired
	private MultipartyServerConfigurationService serverConfig;
	
	@Autowired
	private AccessTokenService acccessTokenService;

	private HttpClient httpClient = HttpClientBuilder.create()
			.useSystemProperties()
			.build();

	private HttpComponentsClientHttpRequestFactory httpFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
	
	private RestTemplate restTemplate = new RestTemplate(httpFactory);

	private JsonParser parser = new JsonParser();
	
	public ClientController() {
		restTemplate.setErrorHandler(new ResponseErrorHandler() {
			
			@Override
			public boolean hasError(ClientHttpResponse response) throws IOException {
				// TODO Auto-generated method stub
				return false;
				
			}
			
			@Override
			public void handleError(ClientHttpResponse response) throws IOException {
				// TODO Auto-generated method stub
				logger.error("HTTP Error");
			}
		});
	}
	
	/**
	 * Simply selects the home view to render by returning its name.
	 */
	@RequestMapping(value = "/", method = RequestMethod.GET)
	public String home(Locale locale, Model model, Principal p) {

		return "home";
	}
	
	@RequestMapping(value = "/fetch", method = RequestMethod.POST, consumes = MimeTypeUtils.APPLICATION_FORM_URLENCODED_VALUE)
	public String fetch(@RequestParam("resource") String resource, Model m, HttpSession session) {
		
		// get the access token if we have one
		String accessTokenValue = acccessTokenService.getAccessToken(resource);

		// send our request to the resource
		
		HttpHeaders headers = new HttpHeaders();
		if (!Strings.isNullOrEmpty(accessTokenValue)) {
			headers.add("Authorization", "Bearer " + accessTokenValue);
		}

		@SuppressWarnings("rawtypes")
		HttpEntity request = new HttpEntity<>(headers);

		ResponseEntity<String> responseEntity = restTemplate.exchange(resource, HttpMethod.GET, request, String.class);

		if (responseEntity.getStatusCode().equals(HttpStatus.OK)) {
			// if we get back data, display it
			JsonObject rso = parser.parse(responseEntity.getBody()).getAsJsonObject();
			m.addAttribute("label", rso.get("label").getAsString());
			m.addAttribute("value", rso.get("value").getAsString());
			return "home";
		} else {
			// if we get back an error, try to get an access token
			List<String> authHeaders = responseEntity.getHeaders().get(HttpHeaders.WWW_AUTHENTICATE);
			// assume there's only one auth header for now
			String authHeader = Iterators.getOnlyElement(authHeaders.iterator());
			
			// parse the header to get the good bits
			String authServerUri = null;
			String ticket = null;
			Iterable<String> parts = Splitter.on(",").split(authHeader.substring("UMA ".length()));
			for (String part : parts) {
				List<String> subparts = Splitter.on("=").splitToList(part.trim());
				if (subparts.get(0).equals("as_uri")) {
					authServerUri = subparts.get(1);
					// strip quotes
					authServerUri = authServerUri.substring(1, authServerUri.length() - 1);
				} else if (subparts.get(0).equals("ticket")) {
					ticket = subparts.get(1);
					// strip quotes
					ticket = ticket.substring(1, ticket.length() - 1);
				}
			}
			
			// find the AS we need to talk to (maybe discover)
			MultipartyServerConfiguration server = serverConfig.getServerConfiguration(authServerUri);
			
			// find the client configuration (maybe register)
			RegisteredClient client = clientConfig.getClientConfiguration(server);
			
			HttpHeaders tokenHeaders = new HttpHeaders();
			tokenHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
			
			// send request to the token endpoint
			MultiValueMap<String, String> params = new LinkedMultiValueMap<>();

			params.add("client_id", client.getClientId());
			params.add("client_secret", client.getClientSecret());
			params.add("grant_type", "urn:ietf:params:oauth:grant_type:multiparty-delegation");
			params.add("ticket", ticket);
			//params.add("scope", "read write");
			
			HttpEntity<MultiValueMap<String, String>> tokenRequest = new HttpEntity<>(params, tokenHeaders);

			
			ResponseEntity<String> tokenResponse = restTemplate.postForEntity(server.getTokenEndpointUri(), tokenRequest, String.class);
			JsonObject o = parser.parse(tokenResponse.getBody()).getAsJsonObject();
			
			if (o.has("error")) {
				if (o.get("error").getAsString().equals("need_info")) {
					// if we get need info, redirect
					
					JsonObject details = o.get("error_details").getAsJsonObject();
					
					// this is the URL to send the user to
					String claimsEndpoint = details.get("requesting_party_claims_endpoint").getAsString();
					String newTicket = details.get("ticket").getAsString();
					
					// set a state value for our return
					String state = UUID.randomUUID().toString();
					session.setAttribute(STATE_SESSION_VAR, state);
					
					// save bits about the request we were trying to make
					session.setAttribute(RESOURCE_SESSION_VAR, resource);
					session.setAttribute(AUTHSERVERURI_SESSION_VAR, authServerUri);
					
					UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(claimsEndpoint)
						.queryParam("client_id", client.getClientId())
						.queryParam("ticket", newTicket)
						.queryParam("claims_redirect_uri", client.getClaimsRedirectUris().iterator().next()) // get the first one and punt
						.queryParam("state", state);
					
					return "redirect:" + builder.build();
				} else {
					// it's an error we don't know how to deal with, give up
					logger.error("Unknown error from token endpoint: " + o.get("error").getAsString());
					return "home";
				}
			} else {
				// if we get an access token, try it again
				
				accessTokenValue = o.get("access_token").getAsString();
				acccessTokenService.saveAccesstoken(resource, accessTokenValue);
				
				headers = new HttpHeaders();
				if (!Strings.isNullOrEmpty(accessTokenValue)) {
					headers.add("Authorization", "Bearer " + accessTokenValue);
				}

				request = new HttpEntity<>(headers);
				
				responseEntity = restTemplate.exchange(resource, HttpMethod.GET, request, String.class);

				if (responseEntity.getStatusCode().equals(HttpStatus.OK)) {
					// if we get back data, display it
					JsonObject rso = parser.parse(responseEntity.getBody()).getAsJsonObject();
					m.addAttribute("label", rso.get("label").getAsString());
					m.addAttribute("value", rso.get("value").getAsString());
					return "home";
				} else {
					logger.error("Unable to get a token");
					return "home";
				}
			}
			
			
		}
	
	}


	@RequestMapping(value = "claims_submitted")
	public String claimsSubmissionCallback(@RequestParam("authorization_state") String authorizationState, @RequestParam("state") String returnState, @RequestParam("ticket") String ticket, HttpSession session, Model m) {
		
		// get our saved information out of the session
		String savedState = (String) session.getAttribute(STATE_SESSION_VAR);
		String savedResource = (String) session.getAttribute(RESOURCE_SESSION_VAR);
		String savedAuthServerUri = (String) session.getAttribute(AUTHSERVERURI_SESSION_VAR);
		
		// make sure the state matches
		if (Strings.isNullOrEmpty(returnState) || !returnState.equals(savedState)) {
			// it's an error if it doesn't
			logger.error("Unable to match states");
			return "home";
		}
		
		if (authorizationState.equals("claims_submitted")) {
			// claims have been submitted, let's go try to get a token again
			// find the AS we need to talk to (maybe discover)
			MultipartyServerConfiguration server = serverConfig.getServerConfiguration(savedAuthServerUri);
			
			// find the client configuration (maybe register)
			RegisteredClient client = clientConfig.getClientConfiguration(server);
			
			HttpHeaders tokenHeaders = new HttpHeaders();
			tokenHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
			
			// send request to the token endpoint
			MultiValueMap<String, String> params = new LinkedMultiValueMap<>();

			params.add("client_id", client.getClientId());
			params.add("client_secret", client.getClientSecret());
			params.add("grant_type", "urn:ietf:params:oauth:grant_type:multiparty-delegation");
			params.add("ticket", ticket);
			//params.add("scope", "read write");
			
			HttpEntity<MultiValueMap<String, String>> tokenRequest = new HttpEntity<>(params, tokenHeaders);

			
			ResponseEntity<String> tokenResponse = restTemplate.postForEntity(server.getTokenEndpointUri(), tokenRequest, String.class);
			JsonObject o = parser.parse(tokenResponse.getBody()).getAsJsonObject();

			if (o.has("error")) {
				if (o.get("error").getAsString().equals("need_info")) {
					// if we get need info, redirect
					
					JsonObject details = o.get("error_details").getAsJsonObject();
					
					// this is the URL to send the user to
					String claimsEndpoint = details.get("requesting_party_claims_endpoint").getAsString();
					String newTicket = details.get("ticket").getAsString();
					
					// set a state value for our return
					String state = UUID.randomUUID().toString();
					session.setAttribute(STATE_SESSION_VAR, state);
					
					// save bits about the request we were trying to make
					session.setAttribute(RESOURCE_SESSION_VAR, savedResource);
					session.setAttribute(AUTHSERVERURI_SESSION_VAR, savedAuthServerUri);
					
					UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(claimsEndpoint)
						.queryParam("client_id", client.getClientId())
						.queryParam("ticket", newTicket)
						.queryParam("claims_redirect_uri", client.getClaimsRedirectUris().iterator().next()) // get the first one and punt
						.queryParam("state", state);
					
					return "redirect:" + builder.build();
				} else {
					// it's an error we don't know how to deal with, give up
					logger.error("Unknown error from token endpoint: " + o.get("error").getAsString());
					return "home";
				}
			} else {
				// if we get an access token, try it again
				
				String accessTokenValue = o.get("access_token").getAsString();
				acccessTokenService.saveAccesstoken(savedResource, accessTokenValue);
				
				HttpHeaders headers = new HttpHeaders();
				if (!Strings.isNullOrEmpty(accessTokenValue)) {
					headers.add("Authorization", "Bearer " + accessTokenValue);
				}

				HttpEntity<Object> request = new HttpEntity<>(headers);
				
				ResponseEntity<String> responseEntity = restTemplate.exchange(savedResource, HttpMethod.GET, request, String.class);

				if (responseEntity.getStatusCode().equals(HttpStatus.OK)) {
					// if we get back data, display it
					JsonObject rso = parser.parse(responseEntity.getBody()).getAsJsonObject();
					m.addAttribute("label", rso.get("label").getAsString());
					m.addAttribute("value", rso.get("value").getAsString());
					return "home";
				} else {
					logger.error("Unable to get a token");
					return "home";
				}
			}
		} else {
			logger.error("Unknown response from claims endpoing: " + authorizationState);
			return "home";
		}
		
	}
	
}
