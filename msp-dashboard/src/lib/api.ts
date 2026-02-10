// Security Prime MSP Dashboard - API Client

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:3000';

// Token storage
let accessToken: string | null = null;
let refreshToken: string | null = null;

// Initialize from localStorage
if (typeof window !== 'undefined') {
	accessToken = localStorage.getItem('accessToken');
	refreshToken = localStorage.getItem('refreshToken');
}

// Types
export interface User {
	id: string;
	email: string;
	name: string;
	role: string;
	organization_id: string | null;
}

export interface Organization {
	id: string;
	name: string;
	slug: string;
	org_type: string;
	parent_id: string | null;
	is_active: boolean;
	max_endpoints: number;
	created_at: string;
}

export interface Endpoint {
	id: string;
	endpoint_id: string;
	organization_id: string;
	hostname: string;
	os_name: string;
	os_version: string;
	agent_version: string;
	last_seen: string;
	status: string;
	security_score: number;
	threats_detected: number;
}

export interface Alert {
	id: string;
	organization_id: string;
	endpoint_id: string | null;
	title: string;
	description: string;
	severity: string;
	status: string;
	source: string;
	created_at: string;
	resolved_at: string | null;
}

export interface DashboardSummary {
	total_organizations: number;
	total_endpoints: number;
	online_endpoints: number;
	offline_endpoints: number;
	critical_alerts: number;
	total_threats_today: number;
	average_security_score: number;
}

export interface LoginResponse {
	token: string;
	refresh_token: string;
	user: User;
	expires_at: string;
}

// API functions

async function request<T>(
	endpoint: string,
	options: RequestInit = {}
): Promise<T> {
	const url = `${API_BASE}${endpoint}`;
	
	const headers: Record<string, string> = {
		'Content-Type': 'application/json',
		...(options.headers as Record<string, string>),
	};
	
	if (accessToken) {
		headers['Authorization'] = `Bearer ${accessToken}`;
	}
	
	const response = await fetch(url, {
		...options,
		headers,
	});
	
	if (response.status === 401) {
		// Try to refresh token
		if (refreshToken) {
			const refreshed = await refreshAccessToken();
			if (refreshed) {
				// Retry request
				return request(endpoint, options);
			}
		}
		// Clear tokens and redirect to login
		clearTokens();
		if (typeof window !== 'undefined') {
			window.location.href = '/login';
		}
		throw new Error('Unauthorized');
	}
	
	if (!response.ok) {
		const error = await response.json().catch(() => ({ message: 'Unknown error' }));
		throw new Error(error.message || `HTTP ${response.status}`);
	}
	
	return response.json();
}

async function refreshAccessToken(): Promise<boolean> {
	try {
		const response = await fetch(`${API_BASE}/api/auth/refresh`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ refresh_token: refreshToken }),
		});
		
		if (response.ok) {
			const data: LoginResponse = await response.json();
			setTokens(data.token, data.refresh_token);
			return true;
		}
	} catch (e) {
		console.error('Token refresh failed:', e);
	}
	return false;
}

function setTokens(access: string, refresh: string) {
	accessToken = access;
	refreshToken = refresh;
	if (typeof window !== 'undefined') {
		localStorage.setItem('accessToken', access);
		localStorage.setItem('refreshToken', refresh);
	}
}

function clearTokens() {
	accessToken = null;
	refreshToken = null;
	if (typeof window !== 'undefined') {
		localStorage.removeItem('accessToken');
		localStorage.removeItem('refreshToken');
	}
}

// Auth API

export async function login(email: string, password: string): Promise<LoginResponse> {
	const response = await request<LoginResponse>('/api/auth/login', {
		method: 'POST',
		body: JSON.stringify({ email, password }),
	});
	
	setTokens(response.token, response.refresh_token);
	return response;
}

export function logout() {
	clearTokens();
	if (typeof window !== 'undefined') {
		window.location.href = '/login';
	}
}

export function isAuthenticated(): boolean {
	return !!accessToken;
}

export function getCurrentUser(): User | null {
	if (typeof window === 'undefined') return null;
	const userJson = localStorage.getItem('currentUser');
	return userJson ? JSON.parse(userJson) : null;
}

export function setCurrentUser(user: User) {
	if (typeof window !== 'undefined') {
		localStorage.setItem('currentUser', JSON.stringify(user));
	}
}

// Dashboard API

export async function getDashboardSummary(): Promise<DashboardSummary> {
	return request<DashboardSummary>('/api/reports/summary');
}

// Organizations API

export async function getOrganizations(): Promise<Organization[]> {
	return request<Organization[]>('/api/organizations');
}

export async function getOrganization(id: string): Promise<Organization> {
	return request<Organization>(`/api/organizations/${id}`);
}

export async function createOrganization(data: {
	name: string;
	org_type: string;
	parent_id?: string;
	max_endpoints?: number;
}): Promise<Organization> {
	return request<Organization>('/api/organizations', {
		method: 'POST',
		body: JSON.stringify(data),
	});
}

// Endpoints API

export async function getEndpoints(): Promise<Endpoint[]> {
	return request<Endpoint[]>('/api/endpoints');
}

export async function getOrganizationEndpoints(orgId: string): Promise<Endpoint[]> {
	return request<Endpoint[]>(`/api/organizations/${orgId}/endpoints`);
}

export async function getEndpoint(id: string): Promise<Endpoint> {
	return request<Endpoint>(`/api/endpoints/${id}`);
}

// Alerts API

export async function getAlerts(): Promise<Alert[]> {
	return request<Alert[]>('/api/alerts');
}

export async function resolveAlert(id: string): Promise<Alert> {
	return request<Alert>(`/api/alerts/${id}/resolve`, {
		method: 'POST',
	});
}

// Users API

export async function getUsers(): Promise<User[]> {
	return request<User[]>('/api/users');
}

export async function createUser(data: {
	email: string;
	password: string;
	name: string;
	role: string;
	organization_id?: string;
}): Promise<User> {
	return request<User>('/api/users', {
		method: 'POST',
		body: JSON.stringify(data),
	});
}
