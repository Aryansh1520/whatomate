<script setup lang="ts">
import { ref, watch, onMounted, onUnmounted, nextTick, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useContactsStore, type Contact, type Message } from '@/stores/contacts'
import { useAuthStore } from '@/stores/auth'
import { useUsersStore } from '@/stores/users'
import { useTransfersStore } from '@/stores/transfers'
import { wsService } from '@/services/websocket'
import { contactsService, chatbotService } from '@/services/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover'
import EmojiPicker from 'vue3-emoji-picker'
import 'vue3-emoji-picker/css'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { toast } from 'vue-sonner'
import {
  Search,
  Send,
  Paperclip,
  Image,
  FileText,
  Smile,
  MoreVertical,
  Phone,
  Video,
  Check,
  CheckCheck,
  Clock,
  AlertCircle,
  User,
  UserPlus,
  UserMinus,
  UserX,
  Play
} from 'lucide-vue-next'
import { formatTime, getInitials, truncate } from '@/lib/utils'
import { useColorMode } from '@/composables/useColorMode'
import CannedResponsePicker from '@/components/chat/CannedResponsePicker.vue'

const route = useRoute()
const router = useRouter()
const contactsStore = useContactsStore()
const authStore = useAuthStore()
const usersStore = useUsersStore()
const transfersStore = useTransfersStore()
const { isDark } = useColorMode()

const messageInput = ref('')
const messagesEndRef = ref<HTMLElement | null>(null)
const isSending = ref(false)
const isAssignDialogOpen = ref(false)
const isTransferring = ref(false)
const isResuming = ref(false)

// File upload state
const fileInputRef = ref<HTMLInputElement | null>(null)
const selectedFile = ref<File | null>(null)
const filePreviewUrl = ref<string | null>(null)
const isMediaDialogOpen = ref(false)
const mediaCaption = ref('')
const isUploadingMedia = ref(false)

// Cache for media blob URLs (message_id -> blob URL)
const mediaBlobUrls = ref<Record<string, string>>({})
const mediaLoadingStates = ref<Record<string, boolean>>({})

// Canned responses slash command state
const cannedPickerOpen = ref(false)
const cannedSearchQuery = ref('')

// Emoji picker state
const emojiPickerOpen = ref(false)

const contactId = computed(() => route.params.contactId as string | undefined)

// Get active transfer for current contact from the store (reactive)
const activeTransfer = computed(() => {
  if (!contactsStore.currentContact) return null
  return transfersStore.getActiveTransferForContact(contactsStore.currentContact.id)
})

const activeTransferId = computed(() => activeTransfer.value?.id || null)

// Check if current user can assign contacts (admin or manager only)
const canAssignContacts = computed(() => {
  // Try store first, then fallback to localStorage
  let role = authStore.userRole
  if (!role || role === 'agent') {
    try {
      const storedUser = localStorage.getItem('user')
      if (storedUser) {
        const user = JSON.parse(storedUser)
        role = user.role
      }
    } catch {
      // ignore
    }
  }
  return role === 'admin' || role === 'manager'
})

// Get list of users for assignment
const assignableUsers = computed(() => {
  return usersStore.users.filter(u => u.is_active)
})

// Initialize WebSocket connection
function initWebSocket() {
  const token = localStorage.getItem('auth_token')
  if (token) {
    wsService.connect(token)
  }
}

// Fetch contacts on mount and connect WebSocket
onMounted(async () => {
  // Ensure auth session is restored
  if (!authStore.isAuthenticated) {
    authStore.restoreSession()
  }

  await contactsStore.fetchContacts()
  initWebSocket()

  // Fetch transfers to track active transfers
  transfersStore.fetchTransfers({ status: 'active' })

  // Fetch users if can assign contacts
  if (canAssignContacts.value) {
    usersStore.fetchUsers().catch(() => {
      // Silently fail if user list can't be loaded
    })
  }

  if (contactId.value) {
    await selectContact(contactId.value)
  }
})

onUnmounted(() => {
  wsService.setCurrentContact(null)
  // Clear current contact when leaving chat view so notifications work on other pages
  contactsStore.setCurrentContact(null)
  // Clean up blob URLs to prevent memory leaks
  Object.values(mediaBlobUrls.value).forEach(url => {
    URL.revokeObjectURL(url)
  })
  mediaBlobUrls.value = {}
})

// Watch for route changes
watch(contactId, async (newId) => {
  if (newId) {
    await selectContact(newId)
  } else {
    wsService.setCurrentContact(null)
    contactsStore.setCurrentContact(null)
    contactsStore.clearMessages()
  }
})

async function selectContact(id: string) {
  const contact = contactsStore.contacts.find(c => c.id === id)
  if (contact) {
    contactsStore.setCurrentContact(contact)
    await contactsStore.fetchMessages(id)
    scrollToBottom()
    // Tell WebSocket server which contact we're viewing
    wsService.setCurrentContact(id)
    // Load media for messages after messages are fetched
    await nextTick()
    try {
      loadMediaForMessages()
    } catch (e) {
      console.error('Error loading media:', e)
    }
  }
}

// Watch for new messages to auto-scroll and load media
watch(() => contactsStore.messages.length, () => {
  scrollToBottom()
  try {
    loadMediaForMessages()
  } catch (e) {
    console.error('Error loading media:', e)
  }
})

// Watch for messages changes to load media
watch(() => contactsStore.messages, () => {
  try {
    loadMediaForMessages()
  } catch (e) {
    console.error('Error loading media:', e)
  }
}, { deep: true })

function handleContactClick(contact: Contact) {
  router.push(`/chat/${contact.id}`)
}

async function sendMessage() {
  if (!messageInput.value.trim() || !contactsStore.currentContact) return

  isSending.value = true
  try {
    await contactsStore.sendMessage(
      contactsStore.currentContact.id,
      'text',
      { body: messageInput.value }
    )
    messageInput.value = ''
    await nextTick()
    scrollToBottom()
  } catch (error) {
    toast.error('Failed to send message')
  } finally {
    isSending.value = false
  }
}

function insertCannedResponse(content: string) {
  messageInput.value = content
  cannedPickerOpen.value = false
  cannedSearchQuery.value = ''
}

function closeCannedPicker() {
  cannedPickerOpen.value = false
  cannedSearchQuery.value = ''
}

function insertEmoji(emoji: string) {
  messageInput.value += emoji
  emojiPickerOpen.value = false
}

// Watch for slash commands in message input
watch(messageInput, (val) => {
  if (val.startsWith('/')) {
    const query = val.slice(1) // Remove the leading /
    cannedSearchQuery.value = query
    cannedPickerOpen.value = true
  } else if (cannedPickerOpen.value) {
    // Close picker if user removes the /
    cannedPickerOpen.value = false
    cannedSearchQuery.value = ''
  }
})

async function assignContactToUser(userId: string | null) {
  if (!contactsStore.currentContact) return

  try {
    await contactsService.assign(contactsStore.currentContact.id, userId)
    toast.success(userId ? 'Contact assigned successfully' : 'Contact unassigned')
    // Refresh contacts list
    await contactsStore.fetchContacts()
  } catch (error: any) {
    const message = error.response?.data?.message || 'Failed to assign contact'
    toast.error(message)
  }
}

async function transferToAgent() {
  if (!contactsStore.currentContact) return

  isTransferring.value = true
  try {
    await chatbotService.createTransfer({
      contact_id: contactsStore.currentContact.id,
      whatsapp_account: contactsStore.currentContact.whatsapp_account,
      source: 'manual'
    })
    toast.success('Contact transferred to agent queue', {
      description: 'Chatbot is now paused for this contact'
    })
    // Refresh transfers store (WebSocket will also update, but this ensures immediate sync)
    await transfersStore.fetchTransfers({ status: 'active' })
  } catch (error: any) {
    const message = error.response?.data?.message || 'Failed to transfer contact'
    toast.error(message)
  } finally {
    isTransferring.value = false
  }
}

async function resumeChatbot() {
  if (!activeTransferId.value) return

  const currentContactId = contactsStore.currentContact?.id
  isResuming.value = true
  try {
    await chatbotService.resumeTransfer(activeTransferId.value)
    toast.success('Chatbot resumed', {
      description: 'The contact will now receive automated responses'
    })
    // Refresh transfers store to update UI
    await transfersStore.fetchTransfers({ status: 'active' })
    // Refresh contacts list (assignment may have changed)
    await contactsStore.fetchContacts()

    // Check if current contact is still in the list (may have been unassigned)
    if (currentContactId) {
      const stillExists = contactsStore.contacts.some(c => c.id === currentContactId)
      if (!stillExists) {
        // Contact no longer visible to this user, navigate away
        contactsStore.setCurrentContact(null)
        contactsStore.clearMessages()
        router.push('/chat')
      }
    }
  } catch (error: any) {
    const message = error.response?.data?.message || 'Failed to resume chatbot'
    toast.error(message)
  } finally {
    isResuming.value = false
  }
}

function scrollToBottom() {
  nextTick(() => {
    if (messagesEndRef.value) {
      messagesEndRef.value.scrollIntoView({ behavior: 'smooth' })
    }
  })
}

function getMessageStatusIcon(status: string) {
  switch (status) {
    case 'sent':
      return Check
    case 'delivered':
      return CheckCheck
    case 'read':
      return CheckCheck
    case 'failed':
      return AlertCircle
    default:
      return Clock
  }
}

function getMessageStatusClass(status: string) {
  switch (status) {
    case 'read':
      return 'text-blue-400' // Bright blue for read
    case 'failed':
      return 'text-destructive'
    default:
      return 'text-muted-foreground' // Gray for sent/delivered
  }
}

function formatMessageTime(dateStr: string) {
  const date = new Date(dateStr)
  return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })
}

function formatContactTime(dateStr?: string) {
  if (!dateStr) return ''
  const date = new Date(dateStr)
  const now = new Date()
  const diffDays = Math.floor((now.getTime() - date.getTime()) / 86400000)

  if (diffDays === 0) {
    return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })
  } else if (diffDays === 1) {
    return 'Yesterday'
  } else if (diffDays < 7) {
    return date.toLocaleDateString('en-US', { weekday: 'short' })
  }
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
}

function getMessageContent(message: Message): string {
  if (message.message_type === 'text') {
    return message.content?.body || ''
  }
  if (message.message_type === 'interactive') {
    // Interactive messages store body text in content (string) or content.body or interactive_data.body
    if (typeof message.content === 'string') {
      return message.content
    }
    if (message.interactive_data?.body) {
      return message.interactive_data.body
    }
    return message.content?.body || '[Interactive Message]'
  }
  // For media messages, return caption if available (media is displayed inline)
  if (message.message_type === 'image' || message.message_type === 'video') {
    return message.content?.body || ''
  }
  if (message.message_type === 'audio') {
    return '' // Audio doesn't have captions
  }
  if (message.message_type === 'document') {
    return message.content?.body || ''
  }
  if (message.message_type === 'template') {
    return '[Template Message]'
  }
  return '[Message]'
}

function getInteractiveButtons(message: Message): Array<{ id: string; title: string }> {
  if (message.message_type !== 'interactive' || !message.interactive_data) {
    return []
  }
  // Handle both "buttons" (<=3) and "rows" (>3 list format)
  const items = message.interactive_data.buttons || message.interactive_data.rows
  if (!items || !Array.isArray(items)) {
    return []
  }
  return items.map((btn: any) => ({
    id: btn.reply?.id || btn.id || '',
    title: btn.reply?.title || btn.title || ''
  }))
}

function isMediaMessage(message: Message): boolean {
  return ['image', 'video', 'audio', 'document'].includes(message.message_type)
}

function getMediaBlobUrl(message: Message): string {
  return mediaBlobUrls.value[message.id] || ''
}

function isMediaLoading(message: Message): boolean {
  return mediaLoadingStates.value[message.id] || false
}

async function loadMediaForMessage(message: Message) {
  if (!message.media_url || mediaBlobUrls.value[message.id] || mediaLoadingStates.value[message.id]) {
    return
  }

  mediaLoadingStates.value[message.id] = true

  try {
    const token = authStore.token
    if (!token) {
      console.error('No auth token available')
      return
    }

    const basePath = ((window as any).__BASE_PATH__ ?? '').replace(/\/$/, '')
    const response = await fetch(`${basePath}/api/media/${message.id}`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })

    if (!response.ok) {
      throw new Error(`Failed to load media: ${response.status}`)
    }

    const blob = await response.blob()
    const blobUrl = URL.createObjectURL(blob)
    mediaBlobUrls.value[message.id] = blobUrl
  } catch (error) {
    console.error('Failed to load media:', error, 'message_id:', message.id)
  } finally {
    mediaLoadingStates.value[message.id] = false
  }
}

// Load media for all messages that have media_url
function loadMediaForMessages() {
  try {
    for (const message of contactsStore.messages) {
      if (message.media_url && !mediaBlobUrls.value[message.id]) {
        // Fire and forget - errors are handled inside loadMediaForMessage
        loadMediaForMessage(message).catch(() => {})
      }
    }
  } catch (e) {
    console.error('Error in loadMediaForMessages:', e)
  }
}

function openMediaPreview(message: Message) {
  const url = getMediaBlobUrl(message)
  if (url) {
    window.open(url, '_blank')
  }
}

function handleImageError(event: Event) {
  const img = event.target as HTMLImageElement
  img.style.display = 'none'
}

function handleMediaError(event: Event, mediaType: string) {
  console.error(`Failed to load ${mediaType}:`, event)
}

// File upload functions
function openFilePicker() {
  fileInputRef.value?.click()
}

function handleFileSelect(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return

  // Validate file type
  const allowedTypes = ['image/', 'video/', 'audio/', 'application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument']
  const isAllowed = allowedTypes.some(type => file.type.startsWith(type))
  if (!isAllowed) {
    toast.error('Unsupported file type', {
      description: 'Please select an image, video, audio, or document file'
    })
    return
  }

  // Validate file size (16MB limit for WhatsApp)
  const maxSize = 16 * 1024 * 1024
  if (file.size > maxSize) {
    toast.error('File too large', {
      description: 'Maximum file size is 16MB'
    })
    return
  }

  selectedFile.value = file
  mediaCaption.value = ''

  // Create preview URL for images and videos
  if (file.type.startsWith('image/') || file.type.startsWith('video/')) {
    filePreviewUrl.value = URL.createObjectURL(file)
  } else {
    filePreviewUrl.value = null
  }

  isMediaDialogOpen.value = true

  // Reset input so same file can be selected again
  input.value = ''
}

function closeMediaDialog() {
  isMediaDialogOpen.value = false
  if (filePreviewUrl.value) {
    URL.revokeObjectURL(filePreviewUrl.value)
    filePreviewUrl.value = null
  }
  selectedFile.value = null
  mediaCaption.value = ''
}

function getMediaType(mimeType: string): string {
  if (mimeType.startsWith('image/')) return 'image'
  if (mimeType.startsWith('video/')) return 'video'
  if (mimeType.startsWith('audio/')) return 'audio'
  return 'document'
}

async function sendMediaMessage() {
  if (!selectedFile.value || !contactsStore.currentContact) return

  isUploadingMedia.value = true
  try {
    const formData = new FormData()
    formData.append('file', selectedFile.value)
    formData.append('contact_id', contactsStore.currentContact.id)
    formData.append('type', getMediaType(selectedFile.value.type))
    if (mediaCaption.value.trim()) {
      formData.append('caption', mediaCaption.value.trim())
    }

    const token = authStore.token
    if (!token) {
      toast.error('Authentication required')
      return
    }

    const basePath = ((window as any).__BASE_PATH__ ?? '').replace(/\/$/, '')
    const response = await fetch(`${basePath}/api/messages/media`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`
      },
      body: formData
    })

    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.message || 'Failed to send media')
    }

    const result = await response.json()

    // Add the message to the store (addMessage has duplicate checking for WebSocket)
    if (result.data) {
      contactsStore.addMessage(result.data)
      scrollToBottom()
      // Load media for the new message
      await nextTick()
      if (result.data.media_url) {
        loadMediaForMessage(result.data)
      }
    }

    toast.success('Media sent successfully')
    closeMediaDialog()
  } catch (error: any) {
    toast.error('Failed to send media', {
      description: error.message || 'Please try again'
    })
  } finally {
    isUploadingMedia.value = false
  }
}
</script>

<template>
  <div class="flex h-full">
    <!-- Contacts List -->
    <div class="w-80 border-r flex flex-col bg-card">
      <!-- Search Header -->
      <div class="p-2 border-b">
        <div class="relative">
          <Search class="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <Input
            v-model="contactsStore.searchQuery"
            placeholder="Search contacts..."
            class="pl-8 h-8 text-sm"
          />
        </div>
      </div>

      <!-- Contacts -->
      <ScrollArea class="flex-1">
        <div class="py-1">
          <div
            v-for="contact in contactsStore.sortedContacts"
            :key="contact.id"
            :class="[
              'flex items-center gap-2 px-3 py-2 cursor-pointer hover:bg-accent transition-colors',
              contactsStore.currentContact?.id === contact.id && 'bg-accent'
            ]"
            @click="handleContactClick(contact)"
          >
            <Avatar class="h-9 w-9">
              <AvatarImage :src="contact.avatar_url" />
              <AvatarFallback class="text-xs">
                {{ getInitials(contact.name || contact.phone_number) }}
              </AvatarFallback>
            </Avatar>
            <div class="flex-1 min-w-0">
              <div class="flex items-center justify-between">
                <p class="text-sm font-medium truncate">
                  {{ contact.name || contact.phone_number }}
                </p>
                <span class="text-[11px] text-muted-foreground">
                  {{ formatContactTime(contact.last_message_at) }}
                </span>
              </div>
              <div class="flex items-center justify-between">
                <p class="text-xs text-muted-foreground truncate">
                  {{ contact.profile_name || contact.phone_number }}
                </p>
                <Badge v-if="contact.unread_count > 0" class="ml-2 h-5 text-[10px]">
                  {{ contact.unread_count }}
                </Badge>
              </div>
            </div>
          </div>

          <div v-if="contactsStore.sortedContacts.length === 0" class="p-3 text-center text-muted-foreground">
            <User class="h-6 w-6 mx-auto mb-1.5 opacity-50" />
            <p class="text-sm">No contacts found</p>
          </div>
        </div>
      </ScrollArea>
    </div>

    <!-- Chat Area -->
    <div class="flex-1 flex flex-col">
      <!-- No Contact Selected -->
      <div
        v-if="!contactsStore.currentContact"
        class="flex-1 flex items-center justify-center text-muted-foreground"
      >
        <div class="text-center">
          <div class="h-16 w-16 rounded-full bg-muted flex items-center justify-center mx-auto mb-4">
            <Send class="h-8 w-8" />
          </div>
          <h3 class="font-medium text-lg mb-1">Select a conversation</h3>
          <p class="text-sm">Choose a contact to start chatting</p>
        </div>
      </div>

      <!-- Chat Interface -->
      <template v-else>
        <!-- Chat Header -->
        <div class="h-12 px-3 border-b flex items-center justify-between bg-card">
          <div class="flex items-center gap-2">
            <Avatar class="h-8 w-8">
              <AvatarImage :src="contactsStore.currentContact.avatar_url" />
              <AvatarFallback class="text-xs">
                {{ getInitials(contactsStore.currentContact.name || contactsStore.currentContact.phone_number) }}
              </AvatarFallback>
            </Avatar>
            <div>
              <div class="flex items-center gap-1.5">
                <p class="text-sm font-medium">
                  {{ contactsStore.currentContact.name || contactsStore.currentContact.phone_number }}
                </p>
                <Badge v-if="activeTransferId" variant="outline" class="text-[10px] h-5 border-orange-500 text-orange-500">
                  Paused
                </Badge>
              </div>
              <p class="text-[11px] text-muted-foreground">
                {{ contactsStore.currentContact.phone_number }}
              </p>
            </div>
          </div>
          <div class="flex items-center gap-1">
            <Tooltip v-if="canAssignContacts">
              <TooltipTrigger as-child>
                <Button variant="ghost" size="icon" class="h-8 w-8" @click="isAssignDialogOpen = true">
                  <UserPlus class="h-4 w-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Assign to agent</TooltipContent>
            </Tooltip>
            <Tooltip>
              <TooltipTrigger as-child>
                <Button variant="ghost" size="icon" class="h-8 w-8">
                  <Phone class="h-4 w-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Voice call</TooltipContent>
            </Tooltip>
            <Tooltip>
              <TooltipTrigger as-child>
                <Button variant="ghost" size="icon" class="h-8 w-8">
                  <Video class="h-4 w-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Video call</TooltipContent>
            </Tooltip>
            <Tooltip v-if="activeTransferId">
              <TooltipTrigger as-child>
                <Button variant="ghost" size="icon" class="h-8 w-8" :disabled="isResuming" @click="resumeChatbot">
                  <Play class="h-4 w-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Resume Chatbot</TooltipContent>
            </Tooltip>
            <DropdownMenu>
              <DropdownMenuTrigger as-child>
                <Button variant="ghost" size="icon" class="h-8 w-8">
                  <MoreVertical class="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuLabel>Contact Options</DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem v-if="canAssignContacts" @click="isAssignDialogOpen = true">
                  <UserPlus class="mr-2 h-4 w-4" />
                  <span>Assign to agent</span>
                </DropdownMenuItem>
                <DropdownMenuItem v-if="!activeTransferId" @click="transferToAgent" :disabled="isTransferring">
                  <UserX class="mr-2 h-4 w-4" />
                  <span>Transfer to Agent</span>
                </DropdownMenuItem>
                <DropdownMenuItem v-if="activeTransferId" @click="resumeChatbot" :disabled="isResuming">
                  <Play class="mr-2 h-4 w-4" />
                  <span>Resume Chatbot</span>
                </DropdownMenuItem>
                <DropdownMenuItem disabled>
                  <User class="mr-2 h-4 w-4" />
                  <span>View contact details</span>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>

        <!-- Messages -->
        <ScrollArea class="flex-1 p-3">
          <div class="space-y-2">
            <div
              v-for="message in contactsStore.messages"
              :key="message.id"
              :class="[
                'flex',
                message.direction === 'outgoing' ? 'justify-end' : 'justify-start'
              ]"
            >
              <div
                :class="[
                  'chat-bubble',
                  message.direction === 'outgoing' ? 'chat-bubble-outgoing' : 'chat-bubble-incoming'
                ]"
              >
                <!-- Image message -->
                <div v-if="message.message_type === 'image' && message.media_url" class="mb-2">
                  <div v-if="isMediaLoading(message)" class="w-[200px] h-[150px] bg-muted rounded-lg animate-pulse flex items-center justify-center">
                    <span class="text-muted-foreground text-sm">Loading...</span>
                  </div>
                  <img
                    v-else-if="getMediaBlobUrl(message)"
                    :src="getMediaBlobUrl(message)"
                    :alt="message.content?.body || 'Image'"
                    class="max-w-[280px] max-h-[300px] rounded-lg cursor-pointer object-cover"
                    @click="openMediaPreview(message)"
                    @error="handleImageError($event)"
                  />
                  <div v-else class="w-[200px] h-[150px] bg-muted rounded-lg flex items-center justify-center">
                    <span class="text-muted-foreground text-sm">[Image]</span>
                  </div>
                </div>
                <!-- Video message -->
                <div v-else-if="message.message_type === 'video' && message.media_url" class="mb-2">
                  <div v-if="isMediaLoading(message)" class="w-[200px] h-[150px] bg-muted rounded-lg animate-pulse flex items-center justify-center">
                    <span class="text-muted-foreground text-sm">Loading...</span>
                  </div>
                  <video
                    v-else-if="getMediaBlobUrl(message)"
                    :src="getMediaBlobUrl(message)"
                    controls
                    class="max-w-[280px] max-h-[300px] rounded-lg"
                    @error="handleMediaError($event, 'video')"
                  />
                  <div v-else class="w-[200px] h-[150px] bg-muted rounded-lg flex items-center justify-center">
                    <span class="text-muted-foreground text-sm">[Video]</span>
                  </div>
                </div>
                <!-- Audio message -->
                <div v-else-if="message.message_type === 'audio' && message.media_url" class="mb-2">
                  <div v-if="isMediaLoading(message)" class="w-[200px] h-[40px] bg-muted rounded-lg animate-pulse"></div>
                  <audio
                    v-else-if="getMediaBlobUrl(message)"
                    :src="getMediaBlobUrl(message)"
                    controls
                    class="max-w-[280px]"
                    @error="handleMediaError($event, 'audio')"
                  />
                  <div v-else class="text-muted-foreground text-sm">[Audio]</div>
                </div>
                <!-- Document message -->
                <div v-else-if="message.message_type === 'document' && message.media_url" class="mb-2">
                  <a
                    v-if="getMediaBlobUrl(message)"
                    :href="getMediaBlobUrl(message)"
                    :download="message.media_filename || 'document'"
                    class="flex items-center gap-2 px-3 py-2 bg-background/50 rounded-lg hover:bg-background/80 transition-colors"
                  >
                    <FileText class="h-5 w-5 text-muted-foreground" />
                    <span class="text-sm truncate max-w-[200px]">
                      {{ message.media_filename || 'Document' }}
                    </span>
                  </a>
                  <div v-else-if="isMediaLoading(message)" class="flex items-center gap-2 px-3 py-2 bg-background/50 rounded-lg">
                    <FileText class="h-5 w-5 text-muted-foreground" />
                    <span class="text-sm text-muted-foreground">Loading...</span>
                  </div>
                  <div v-else class="flex items-center gap-2 px-3 py-2 bg-background/50 rounded-lg">
                    <FileText class="h-5 w-5 text-muted-foreground" />
                    <span class="text-sm text-muted-foreground">[Document]</span>
                  </div>
                </div>
                <!-- Text content (for text messages or captions) -->
                <p v-if="getMessageContent(message)" class="whitespace-pre-wrap break-words">{{ getMessageContent(message) }}</p>
                <!-- Fallback for media without URL -->
                <p v-else-if="isMediaMessage(message) && !message.media_url" class="text-muted-foreground italic">
                  [{{ message.message_type.charAt(0).toUpperCase() + message.message_type.slice(1) }}]
                </p>
                <!-- Interactive buttons -->
                <div
                  v-if="getInteractiveButtons(message).length > 0"
                  class="mt-2 space-y-1"
                >
                  <div
                    v-for="btn in getInteractiveButtons(message)"
                    :key="btn.id"
                    class="px-3 py-1.5 text-sm text-center border rounded-lg bg-background/50"
                  >
                    {{ btn.title }}
                  </div>
                </div>
                <div
                  :class="[
                    'chat-bubble-time flex items-center gap-1',
                    message.direction === 'outgoing' ? 'justify-end' : 'justify-start'
                  ]"
                >
                  <span>{{ formatMessageTime(message.created_at) }}</span>
                  <component
                    v-if="message.direction === 'outgoing'"
                    :is="getMessageStatusIcon(message.status)"
                    :class="['h-3 w-3', getMessageStatusClass(message.status)]"
                  />
                </div>
              </div>
            </div>
            <div ref="messagesEndRef" />
          </div>
        </ScrollArea>

        <!-- Message Input -->
        <div class="px-3 py-2 border-t bg-card">
          <form @submit.prevent="sendMessage" class="flex items-end gap-1.5">
            <div class="flex">
              <Tooltip>
                <TooltipTrigger as-child>
                  <span>
                    <Popover v-model:open="emojiPickerOpen">
                      <PopoverTrigger as-child>
                        <Button type="button" variant="ghost" size="icon" class="h-8 w-8">
                          <Smile class="h-4 w-4" />
                        </Button>
                      </PopoverTrigger>
                      <PopoverContent side="top" align="start" class="w-auto p-0">
                        <EmojiPicker
                          :native="true"
                          :disable-skin-tones="true"
                          :theme="isDark ? 'dark' : 'light'"
                          @select="insertEmoji($event.i)"
                        />
                      </PopoverContent>
                    </Popover>
                  </span>
                </TooltipTrigger>
                <TooltipContent>Emoji</TooltipContent>
              </Tooltip>
              <Tooltip>
                <TooltipTrigger as-child>
                  <span>
                    <CannedResponsePicker
                      :contact="contactsStore.currentContact"
                      :external-open="cannedPickerOpen"
                      :external-search="cannedSearchQuery"
                      @select="insertCannedResponse"
                      @close="closeCannedPicker"
                    />
                  </span>
                </TooltipTrigger>
                <TooltipContent>Canned Responses</TooltipContent>
              </Tooltip>
              <Tooltip>
                <TooltipTrigger as-child>
                  <Button type="button" variant="ghost" size="icon" class="h-8 w-8" @click="openFilePicker">
                    <Paperclip class="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Attach file</TooltipContent>
              </Tooltip>
              <input
                ref="fileInputRef"
                type="file"
                accept="image/*,video/*,audio/*,.pdf,.doc,.docx"
                class="hidden"
                @change="handleFileSelect"
              />
            </div>
            <Textarea
              v-model="messageInput"
              placeholder="Type a message..."
              class="flex-1 min-h-[36px] max-h-[100px] resize-none text-sm"
              :rows="1"
              @keydown.enter.exact.prevent="sendMessage"
            />
            <Tooltip>
              <TooltipTrigger as-child>
                <Button
                  type="submit"
                  size="icon"
                  class="h-8 w-8"
                  :disabled="!messageInput.trim() || isSending"
                >
                  <Send class="h-4 w-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Send message</TooltipContent>
            </Tooltip>
          </form>
        </div>
      </template>
    </div>

    <!-- Assign Contact Dialog -->
    <Dialog v-model:open="isAssignDialogOpen">
      <DialogContent class="max-w-sm">
        <DialogHeader>
          <DialogTitle>Assign Contact</DialogTitle>
          <DialogDescription>
            Select a team member to assign this contact to.
          </DialogDescription>
        </DialogHeader>
        <div class="py-4 space-y-2">
          <Button
            variant="outline"
            class="w-full justify-start"
            @click="assignContactToUser(null); isAssignDialogOpen = false"
          >
            <UserMinus class="mr-2 h-4 w-4" />
            Unassign
          </Button>
          <Separator />
          <Button
            v-for="user in assignableUsers"
            :key="user.id"
            variant="ghost"
            class="w-full justify-start"
            @click="assignContactToUser(user.id); isAssignDialogOpen = false"
          >
            <User class="mr-2 h-4 w-4" />
            <span>{{ user.full_name }}</span>
            <Badge variant="outline" class="ml-auto text-xs">
              {{ user.role }}
            </Badge>
          </Button>
        </div>
      </DialogContent>
    </Dialog>

    <!-- Media Preview Dialog -->
    <Dialog v-model:open="isMediaDialogOpen">
      <DialogContent class="max-w-md">
        <DialogHeader>
          <DialogTitle>Send Media</DialogTitle>
          <DialogDescription>
            {{ selectedFile?.name }}
          </DialogDescription>
        </DialogHeader>
        <div class="py-4 space-y-4">
          <!-- Image preview -->
          <div v-if="selectedFile?.type.startsWith('image/') && filePreviewUrl" class="flex justify-center">
            <img
              :src="filePreviewUrl"
              :alt="selectedFile.name"
              class="max-w-full max-h-[300px] rounded-lg object-contain"
            />
          </div>
          <!-- Video preview -->
          <div v-else-if="selectedFile?.type.startsWith('video/') && filePreviewUrl" class="flex justify-center">
            <video
              :src="filePreviewUrl"
              controls
              class="max-w-full max-h-[300px] rounded-lg"
            />
          </div>
          <!-- Audio preview -->
          <div v-else-if="selectedFile?.type.startsWith('audio/')" class="flex justify-center">
            <div class="flex items-center gap-3 px-4 py-3 bg-muted rounded-lg">
              <div class="h-10 w-10 rounded-full bg-primary/10 flex items-center justify-center">
                <Paperclip class="h-5 w-5 text-primary" />
              </div>
              <div>
                <p class="font-medium text-sm">{{ selectedFile.name }}</p>
                <p class="text-xs text-muted-foreground">Audio file</p>
              </div>
            </div>
          </div>
          <!-- Document preview -->
          <div v-else-if="selectedFile" class="flex justify-center">
            <div class="flex items-center gap-3 px-4 py-3 bg-muted rounded-lg">
              <div class="h-10 w-10 rounded-full bg-primary/10 flex items-center justify-center">
                <FileText class="h-5 w-5 text-primary" />
              </div>
              <div>
                <p class="font-medium text-sm truncate max-w-[200px]">{{ selectedFile.name }}</p>
                <p class="text-xs text-muted-foreground">
                  {{ (selectedFile.size / 1024).toFixed(1) }} KB
                </p>
              </div>
            </div>
          </div>

          <!-- Caption input (not for audio) -->
          <div v-if="selectedFile && !selectedFile.type.startsWith('audio/')">
            <Textarea
              v-model="mediaCaption"
              placeholder="Add a caption..."
              class="min-h-[60px] max-h-[100px] resize-none"
              :rows="2"
            />
          </div>

          <!-- Actions -->
          <div class="flex justify-end gap-2">
            <Button variant="outline" @click="closeMediaDialog" :disabled="isUploadingMedia">
              Cancel
            </Button>
            <Button @click="sendMediaMessage" :disabled="isUploadingMedia">
              <Send v-if="!isUploadingMedia" class="mr-2 h-4 w-4" />
              <span v-if="isUploadingMedia">Sending...</span>
              <span v-else>Send</span>
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  </div>
</template>
