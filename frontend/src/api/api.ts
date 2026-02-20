import client from './client'
import type {
  APIKeys,
  IOC,
  IPCheckResult,
  PaginatedResponse,
  ToolRunResult,
  User,
  VaultFile,
  VaultFileDetail,
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

  getUser: () => client.get<User>('/auth/user/'),

  updateUser: (data: Partial<Pick<User, 'email'>>) =>
    client.patch<User>('/auth/user/', data),
}

// ---- Files ----
export const filesApi = {
  list: (params?: { search?: string; page?: number }) =>
    client.get<PaginatedResponse<VaultFile>>('/files/', { params }),

  get: (id: number) => client.get<VaultFileDetail>(`/files/${id}/`),

  upload: (formData: FormData) =>
    client.post<VaultFile>('/files/', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    }),

  fetchUrl: (url: string, tags?: string) =>
    client.post<VaultFile>('/files/fetch_url/', { url, tags }),

  delete: (id: number) => client.delete(`/files/${id}/`),

  download: (id: number) =>
    client.get(`/files/${id}/download/`, { responseType: 'blob' }),

  runTool: (id: number, tool: string, sub_tool?: string, password?: string) =>
    client.post<ToolRunResult>(`/files/${id}/run_tool/`, { tool, sub_tool, password }),

  addTag: (id: number, tag: string) =>
    client.post<{ tags: string[] }>(`/files/${id}/add_tag/`, { tag }),

  removeTag: (id: number, tag: string) =>
    client.post<{ tags: string[] }>(`/files/${id}/remove_tag/`, { tag }),

  vtDownload: (sha256: string, tags?: string) =>
    client.post<VaultFile>('/files/vt-download/', { sha256, tags }),

  mbDownload: (sha256: string, tags?: string) =>
    client.post<VaultFile>('/files/mb-download/', { sha256, tags }),
}

// ---- IOCs ----
export const iocsApi = {
  list: (params?: { filter?: 'true' | 'false' | 'both'; search?: string; page?: number }) =>
    client.get<PaginatedResponse<IOC>>('/iocs/', { params }),

  update: (id: number, data: Partial<IOC>) =>
    client.patch<IOC>(`/iocs/${id}/`, data),
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

// ---- IP intelligence ----
export const intelApi = {
  checkIP: (ip: string) =>
    client.post<IPCheckResult>('/intel/ip/', { ip }),
}

// ---- API key manager ----
export const adminApi = {
  getKeys: () => client.get<APIKeys>('/admin/keys/'),
  setKey: (key: string, value: string) =>
    client.post<{ status: string; key: string }>('/admin/keys/', { key, value }),
}
