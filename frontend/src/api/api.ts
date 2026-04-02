import client from './client'
import type {
  AnalysisResult,
  APIKeys,
  AttackTechnique,
  Comment,
  DomainCheckResult,
  IOC,
  IPCheckResult,
  PaginatedResponse,
  SimilarFile,
  ToolRunResult,
  User,
  VaultFile,
  VaultFileDetail,
  VtData,
  YaraRule,
} from '../types'

// ---- Auth ----
export const authApi = {
  login: (username: string, password: string) =>
    client.post<{ access: string; refresh: string }>('/auth/token/', { username, password }),

  refresh: (refresh: string) =>
    client.post<{ access: string; refresh?: string }>('/auth/token/refresh/', { refresh }),

  register: (username: string, email: string, password: string, password2: string) =>
    client.post<{ id: number; username: string }>('/auth/register/', {
      username,
      email,
      password,
      password2,
    }),

  logout: (refresh: string) =>
    client.post('/auth/logout/', { refresh }),

  getUser: () => client.get<User>('/auth/user/'),

  updateUser: (data: Partial<Pick<User, 'email'>>) =>
    client.patch<User>('/auth/user/', data),
}

// ---- Files ----
export const filesApi = {
  list: (params?: { search?: string; page?: number; file_type?: string }) =>
    client.get<PaginatedResponse<VaultFile>>('/files/', { params }),

  get: (sha256: string) => client.get<VaultFileDetail>(`/files/${sha256}/`),

  upload: (formData: FormData) =>
    client.post<VaultFile>('/files/', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    }),

  fetchUrl: (url: string, tags?: string) =>
    client.post<VaultFile>('/files/fetch_url/', { url, tags }),

  delete: (sha256: string) => client.delete(`/files/${sha256}/`),

  download: (sha256: string) =>
    client.get(`/files/${sha256}/download/`, { responseType: 'blob' }),

  runTool: (sha256: string, tool: string, sub_tool?: string, password?: string) =>
    client.post<ToolRunResult>(`/files/${sha256}/run_tool/`, { tool, sub_tool, password }),

  addTag: (sha256: string, tag: string) =>
    client.post<{ tags: string[] }>(`/files/${sha256}/add_tag/`, { tag }),

  removeTag: (sha256: string, tag: string) =>
    client.post<{ tags: string[] }>(`/files/${sha256}/remove_tag/`, { tag }),

  vtDownload: (sha256: string, tags?: string) =>
    client.post<VaultFile>('/files/vt-download/', { sha256, tags }),

  mbDownload: (sha256: string, tags?: string) =>
    client.post<VaultFile>('/files/mb-download/', { sha256, tags }),

  getComments: (sha256: string) =>
    client.get<Comment[]>(`/files/${sha256}/comments/`),

  addComment: (sha256: string, title: string, text: string, comment_type = 'note') =>
    client.post<Comment>(`/files/${sha256}/comments/`, { title, text, comment_type }),

  vtEnrich: (sha256: string) =>
    client.post<{ vt_data: VtData }>(`/files/${sha256}/vt-enrich/`),

  mbLookup: (sha256: string) =>
    client.post<{ mb_data: Record<string, unknown> }>(`/files/${sha256}/mb-lookup/`),

  getAnalysisResults: (sha256: string, tool?: string) =>
    client.get<AnalysisResult[]>(`/files/${sha256}/analysis_results/`, { params: tool ? { tool } : {} }),

  vtBehaviour: (sha256: string) =>
    client.get<Record<string, unknown>>(`/files/${sha256}/vt_behaviour/`),

  getSimilar: (sha256: string, threshold?: number) =>
    client.get<SimilarFile[]>(`/files/${sha256}/similar/`, { params: threshold !== undefined ? { threshold } : {} }),

  mapAttack: (sha256: string) =>
    client.post<{ techniques: AttackTechnique[] }>(`/files/${sha256}/map-attack/`),

  stixExport: (sha256: string) =>
    client.get(`/files/${sha256}/stix/`, { responseType: 'blob' }),
}

// ---- IOCs ----
export const iocsApi = {
  list: (params?: { filter?: 'true' | 'false' | 'both'; search?: string; page?: number; ioc_type?: string }) =>
    client.get<PaginatedResponse<IOC>>('/iocs/', { params }),

  update: (id: number, data: Partial<Pick<IOC, 'true_or_false'>>) =>
    client.patch<IOC>(`/iocs/${id}/`, data),

  enrich: (id: number) =>
    client.post<IOC>(`/iocs/${id}/enrich/`),

  getSamples: (id: number) =>
    client.get<VaultFile[]>(`/iocs/${id}/samples/`),

  exportStix: (ids: number[]) =>
    client.post('/iocs/export-stix/', { ids }, { responseType: 'blob' }),

  bulkDelete: (ids: number[]) =>
    client.post<{ deleted: number }>('/iocs/bulk-delete/', { ids }),
}

// ---- YARA rules ----
export const yaraApi = {
  list: () => client.get<YaraRule[]>('/yara/'),
  get: (name: string) => client.get<YaraRule>(`/yara/${name}/`),
  create: (name: string, content: string) =>
    client.post<YaraRule>('/yara/', { name, content }),
  update: (name: string, content: string) =>
    client.put<YaraRule>(`/yara/${name}/`, { content }),
  delete: (name: string) => client.delete(`/yara/${name}/`),
}

// ---- IP / domain intelligence ----
export const intelApi = {
  checkIP: (ip: string) =>
    client.post<IPCheckResult>('/intel/ip/', { ip }),

  checkDomain: (domain: string) =>
    client.post<DomainCheckResult>('/intel/domain/', { domain }),
}

// ---- Standalone tools ----
export const toolsApi = {
  qrDecode: (file: File) => {
    const fd = new FormData()
    fd.append('file', file)
    return client.post<{ result: string }>('/tools/qr-decode/', fd, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
  },
}

// ---- API key manager ----
export const adminApi = {
  getKeys: () => client.get<APIKeys>('/admin/keys/'),
  setKey: (key: string, value: string) =>
    client.post<{ status: string; key: string }>('/admin/keys/', { key, value }),
}
