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

package org.mitreid.multiparty.model;

import java.util.Set;

import org.mitre.openid.connect.config.ServerConfiguration;

/**
 * @author jricher
 *
 */
public class MultipartyServerConfiguration extends ServerConfiguration {

	/*

		m.put("issuer", issuer);
		m.put("pat_profiles_supported", tokenProfiles);
		m.put("rpt_profiles_supported", tokenProfiles);
		m.put("pat_grant_types_supported", grantTypes);
		m.put("claim_token_profiles_supported", ImmutableSet.of());
		m.put("uma_profiles_supported", ImmutableSet.of());
		m.put("registration_endpoint", issuer + DynamicClientRegistrationEndpoint.URL);
		m.put("token_endpoint", issuer + "token");
		m.put("authorization_endpoint", issuer + "authorize");
		m.put("requesting_party_claims_endpoint", issuer + ClaimsCollectionEndpoint.URL);
		m.put("introspection_endpoint", issuer + IntrospectionEndpoint.URL);
		m.put("resource_set_registration_endpoint", issuer + ResourceSetRegistrationEndpoint.URL);
		m.put("permission_registration_endpoint", issuer + PermissionRegistrationEndpoint.URL);

	 */

	private Set<String> patProfilesSupported;
	private Set<String> rptProfilesSupported;
	private Set<String> patGrantTypesSupported;
	private Set<String> claimTokenProfilesSupported;
	private Set<String> umaProfilesSupported;
	private String requestingPartyClaimsEndpoint;
	private String resourceSetRegistrationEndpoint;
	private String permissionRegistrationEndpoint;
	/**
	 * @return the patProfilesSupported
	 */
	public Set<String> getPatProfilesSupported() {
		return patProfilesSupported;
	}
	/**
	 * @param patProfilesSupported the patProfilesSupported to set
	 */
	public void setPatProfilesSupported(Set<String> patProfilesSupported) {
		this.patProfilesSupported = patProfilesSupported;
	}
	/**
	 * @return the rptProfilesSupported
	 */
	public Set<String> getRptProfilesSupported() {
		return rptProfilesSupported;
	}
	/**
	 * @param rptProfilesSupported the rptProfilesSupported to set
	 */
	public void setRptProfilesSupported(Set<String> rptProfilesSupported) {
		this.rptProfilesSupported = rptProfilesSupported;
	}
	/**
	 * @return the claimTokenProfilesSupported
	 */
	public Set<String> getClaimTokenProfilesSupported() {
		return claimTokenProfilesSupported;
	}
	/**
	 * @param claimTokenProfilesSupported the claimTokenProfilesSupported to set
	 */
	public void setClaimTokenProfilesSupported(Set<String> claimTokenProfilesSupported) {
		this.claimTokenProfilesSupported = claimTokenProfilesSupported;
	}
	/**
	 * @return the umaProfilesSupported
	 */
	public Set<String> getUmaProfilesSupported() {
		return umaProfilesSupported;
	}
	/**
	 * @param umaProfilesSupported the umaProfilesSupported to set
	 */
	public void setUmaProfilesSupported(Set<String> umaProfilesSupported) {
		this.umaProfilesSupported = umaProfilesSupported;
	}
	/**
	 * @return the requestingPartyClaimsEndpoint
	 */
	public String getRequestingPartyClaimsEndpoint() {
		return requestingPartyClaimsEndpoint;
	}
	/**
	 * @param requestingPartyClaimsEndpoint the requestingPartyClaimsEndpoint to set
	 */
	public void setRequestingPartyClaimsEndpoint(String requestingPartyClaimsEndpoint) {
		this.requestingPartyClaimsEndpoint = requestingPartyClaimsEndpoint;
	}
	/**
	 * @return the resourceSetRegistrationEndpoint
	 */
	public String getResourceSetRegistrationEndpoint() {
		return resourceSetRegistrationEndpoint;
	}
	/**
	 * @param resourceSetRegistrationEndpoint the resourceSetRegistrationEndpoint to set
	 */
	public void setResourceSetRegistrationEndpoint(String resourceSetRegistrationEndpoint) {
		this.resourceSetRegistrationEndpoint = resourceSetRegistrationEndpoint;
	}
	/**
	 * @return the permissionRegistrationEndpoint
	 */
	public String getPermissionRegistrationEndpoint() {
		return permissionRegistrationEndpoint;
	}
	/**
	 * @param permissionRegistrationEndpoint the permissionRegistrationEndpoint to set
	 */
	public void setPermissionRegistrationEndpoint(String permissionRegistrationEndpoint) {
		this.permissionRegistrationEndpoint = permissionRegistrationEndpoint;
	}
	/**
	 * @return the patGrantTypesSupported
	 */
	public Set<String> getPatGrantTypesSupported() {
		return patGrantTypesSupported;
	}
	/**
	 * @param patGrantTypesSupported the patGrantTypesSupported to set
	 */
	public void setPatGrantTypesSupported(Set<String> patGrantTypesSupported) {
		this.patGrantTypesSupported = patGrantTypesSupported;
	}
	
}
