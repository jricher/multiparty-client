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

package org.mitreid.multiparty.service;

import static org.mitre.util.JsonUtils.getAsString;

import java.util.concurrent.ExecutionException;

import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.mitre.util.JsonUtils;
import org.mitreid.multiparty.model.MultipartyServerConfiguration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.UncheckedExecutionException;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * @author jricher
 *
 */
@Service
public class DynamicMultipartyServerConfigurationService implements MultipartyServerConfigurationService {

	// map of issuer -> server configuration, loaded dynamically from service discovery
	private LoadingCache<String, MultipartyServerConfiguration> servers;
	
	public DynamicMultipartyServerConfigurationService() {
		servers = CacheBuilder.newBuilder().build(new MultipartyServiceConfigurationFetcher());
	}

	/* (non-Javadoc)
	 * @see org.mitreid.multiparty.service.MultipartyServerConfigurationService#getServerConfiguration(java.lang.String)
	 */
	@Override
	public MultipartyServerConfiguration getServerConfiguration(String issuer) {
		try {
			return servers.get(issuer);
		} catch (UncheckedExecutionException | ExecutionException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * @author jricher
	 *
	 */
	private class MultipartyServiceConfigurationFetcher extends CacheLoader<String, MultipartyServerConfiguration> {
		private HttpClient httpClient = HttpClientBuilder.create()
				.useSystemProperties()
				.build();
		private HttpComponentsClientHttpRequestFactory httpFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
		private JsonParser parser = new JsonParser();

		@Override
		public MultipartyServerConfiguration load(String issuer) throws Exception {
			RestTemplate restTemplate = new RestTemplate(httpFactory);

			// data holder
			MultipartyServerConfiguration conf = new MultipartyServerConfiguration();

			// construct the well-known URI
			String url = issuer + "/.well-known/uma-configuration";

			// fetch the value
			String jsonString = restTemplate.getForObject(url, String.class);

			JsonElement parsed = parser.parse(jsonString);
			if (parsed.isJsonObject()) {

				JsonObject o = parsed.getAsJsonObject();

				// sanity checks
				if (!o.has("issuer")) {
					throw new IllegalStateException("Returned object did not have an 'issuer' field");
				}

				conf.setIssuer(o.get("issuer").getAsString());
				conf.setPatProfilesSupported(JsonUtils.getAsStringSet(o, "pat_profiles_supported"));
				conf.setRptProfilesSupported(JsonUtils.getAsStringSet(o, "rpt_profiles_supported"));
				conf.setPatGrantTypesSupported(JsonUtils.getAsStringSet(o, "pat_grant_types_supported"));
				conf.setClaimTokenProfilesSupported(JsonUtils.getAsStringSet(o, "claim_token_profiles_supported"));
				conf.setUmaProfilesSupported(JsonUtils.getAsStringSet(o, "uma_profiles_supported"));
				conf.setRequestingPartyClaimsEndpoint(JsonUtils.getAsString(o, "requesting_party_claims_endpoint"));
				conf.setResourceSetRegistrationEndpoint(JsonUtils.getAsString(o, "resource_set_registration_endpoint"));
				conf.setPermissionRegistrationEndpoint(JsonUtils.getAsString(o, "permission_registration_endpoint"));
				conf.setAuthorizationEndpointUri(getAsString(o, "authorization_endpoint"));
				conf.setTokenEndpointUri(getAsString(o, "token_endpoint"));
				conf.setRegistrationEndpointUri(getAsString(o, "registration_endpoint"));
				conf.setIntrospectionEndpointUri(getAsString(o, "introspection_endpoint"));

				return conf;
			} else {
				throw new IllegalStateException("Couldn't parse server discovery results for " + url);
			}

		}

	}


}
