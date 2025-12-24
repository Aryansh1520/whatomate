<script setup lang="ts">
import { ref, computed } from 'vue'
import { RouterLink, RouterView, useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { Button } from '@/components/ui/button'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import { Separator } from '@/components/ui/separator'
import { ScrollArea } from '@/components/ui/scroll-area'
import {
  Popover,
  PopoverContent,
  PopoverTrigger
} from '@/components/ui/popover'
import {
  LayoutDashboard,
  MessageSquare,
  Bot,
  FileText,
  Megaphone,
  Settings,
  LogOut,
  ChevronLeft,
  ChevronRight,
  Users,
  Workflow,
  Sparkles,
  Key,
  User,
  UserX,
  MessageSquareText,
  Sun,
  Moon,
  Monitor
} from 'lucide-vue-next'
import { useColorMode } from '@/composables/useColorMode'
import { getInitials } from '@/lib/utils'

const route = useRoute()
const router = useRouter()
const authStore = useAuthStore()
const isCollapsed = ref(false)
const isUserMenuOpen = ref(false)
const { colorMode, isDark, setColorMode } = useColorMode()

// Define all navigation items with role requirements
const allNavItems = [
  {
    name: 'Dashboard',
    path: '/',
    icon: LayoutDashboard,
    roles: ['admin', 'manager']
  },
  {
    name: 'Chat',
    path: '/chat',
    icon: MessageSquare,
    roles: ['admin', 'manager', 'agent']
  },
  {
    name: 'Chatbot',
    path: '/chatbot',
    icon: Bot,
    roles: ['admin', 'manager'],
    children: [
      { name: 'Overview', path: '/chatbot', icon: Bot },
      { name: 'Settings', path: '/chatbot/settings', icon: Settings },
      { name: 'Keywords', path: '/chatbot/keywords', icon: Key },
      { name: 'Flows', path: '/chatbot/flows', icon: Workflow },
      { name: 'AI Contexts', path: '/chatbot/ai', icon: Sparkles }
    ]
  },
  {
    name: 'Transfers',
    path: '/chatbot/transfers',
    icon: UserX,
    roles: ['admin', 'manager', 'agent']
  },
  {
    name: 'Templates',
    path: '/templates',
    icon: FileText,
    roles: ['admin', 'manager']
  },
  {
    name: 'Flows',
    path: '/flows',
    icon: Workflow,
    roles: ['admin', 'manager']
  },
  {
    name: 'Campaigns',
    path: '/campaigns',
    icon: Megaphone,
    roles: ['admin', 'manager']
  },
  {
    name: 'Settings',
    path: '/settings',
    icon: Settings,
    roles: ['admin', 'manager'],
    children: [
      { name: 'General', path: '/settings', icon: Settings },
      { name: 'Accounts', path: '/settings/accounts', icon: Users },
      { name: 'Canned Responses', path: '/settings/canned-responses', icon: MessageSquareText },
      { name: 'Users', path: '/settings/users', icon: Users, roles: ['admin'] },
      { name: 'API Keys', path: '/settings/api-keys', icon: Key, roles: ['admin'] }
    ]
  }
]

// Filter navigation based on user role
const navigation = computed(() => {
  const userRole = authStore.userRole || 'agent'

  return allNavItems
    .filter(item => item.roles.includes(userRole))
    .map(item => ({
      ...item,
      active: item.path === '/'
        ? route.name === 'dashboard'
        : item.path === '/chat'
          ? route.name === 'chat' || route.name === 'chat-conversation'
          : route.path.startsWith(item.path),
      children: item.children?.filter(
        child => !child.roles || child.roles.includes(userRole)
      )
    }))
})

const toggleSidebar = () => {
  isCollapsed.value = !isCollapsed.value
}

const handleLogout = async () => {
  await authStore.logout()
  router.push('/login')
}
</script>

<template>
  <div class="flex h-screen bg-background">
    <!-- Sidebar -->
    <aside
      :class="[
        'flex flex-col border-r bg-card transition-all duration-300',
        isCollapsed ? 'w-16' : 'w-64'
      ]"
    >
      <!-- Logo -->
      <div class="flex h-12 items-center justify-between px-3 border-b">
        <RouterLink to="/" class="flex items-center gap-2">
          <div class="h-7 w-7 rounded-md bg-primary flex items-center justify-center">
            <MessageSquare class="h-4 w-4 text-primary-foreground" />
          </div>
          <span
            v-if="!isCollapsed"
            class="font-semibold text-sm text-foreground"
          >
            Whatomate
          </span>
        </RouterLink>
        <Button
          variant="ghost"
          size="icon"
          class="h-7 w-7"
          @click="toggleSidebar"
        >
          <ChevronLeft v-if="!isCollapsed" class="h-3.5 w-3.5" />
          <ChevronRight v-else class="h-3.5 w-3.5" />
        </Button>
      </div>

      <!-- Navigation -->
      <ScrollArea class="flex-1 py-2">
        <nav class="space-y-0.5 px-2">
          <template v-for="item in navigation" :key="item.path">
            <RouterLink
              :to="item.path"
              :class="[
                'flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-[13px] font-medium transition-colors',
                item.active
                  ? 'bg-primary/10 text-primary'
                  : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground',
                isCollapsed && 'justify-center px-2'
              ]"
            >
              <component :is="item.icon" class="h-4 w-4 shrink-0" />
              <span v-if="!isCollapsed">{{ item.name }}</span>
            </RouterLink>

            <!-- Submenu items -->
            <template v-if="item.children && item.active && !isCollapsed">
              <RouterLink
                v-for="child in item.children"
                :key="child.path"
                :to="child.path"
                :class="[
                  'flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-[13px] font-medium transition-colors ml-4',
                  route.path === child.path
                    ? 'bg-primary/10 text-primary'
                    : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
                ]"
              >
                <component :is="child.icon" class="h-3.5 w-3.5 shrink-0" />
                <span>{{ child.name }}</span>
              </RouterLink>
            </template>
          </template>
        </nav>
      </ScrollArea>

      <!-- User section -->
      <div class="border-t p-2">
        <Popover v-model:open="isUserMenuOpen">
          <PopoverTrigger as-child>
            <Button
              variant="ghost"
              :class="[
                'flex items-center w-full h-auto px-2 py-1.5 gap-2',
                isCollapsed && 'justify-center'
              ]"
            >
              <Avatar class="h-7 w-7">
                <AvatarImage :src="undefined" />
                <AvatarFallback class="text-xs">
                  {{ getInitials(authStore.user?.full_name || 'U') }}
                </AvatarFallback>
              </Avatar>
              <div v-if="!isCollapsed" class="flex flex-col items-start text-left">
                <span class="text-[13px] font-medium truncate max-w-[140px]">
                  {{ authStore.user?.full_name }}
                </span>
                <span class="text-[11px] text-muted-foreground truncate max-w-[140px]">
                  {{ authStore.user?.email }}
                </span>
              </div>
            </Button>
          </PopoverTrigger>
          <PopoverContent side="top" align="start" class="w-52 p-1.5">
            <div class="text-xs font-medium px-2 py-1 text-muted-foreground">My Account</div>
            <Separator class="my-1" />
            <RouterLink to="/profile">
              <Button
                variant="ghost"
                class="w-full justify-start px-2 py-1 h-auto text-[13px] font-normal"
                @click="isUserMenuOpen = false"
              >
                <User class="mr-2 h-3.5 w-3.5" />
                <span>Profile</span>
              </Button>
            </RouterLink>
            <Separator class="my-1" />
            <div class="text-xs font-medium px-2 py-1 text-muted-foreground">Theme</div>
            <div class="flex gap-0.5 px-1.5 py-1">
              <Button
                variant="ghost"
                size="icon"
                class="h-7 w-7"
                :class="colorMode === 'light' && 'bg-accent'"
                @click="setColorMode('light')"
              >
                <Sun class="h-3.5 w-3.5" />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                class="h-7 w-7"
                :class="colorMode === 'dark' && 'bg-accent'"
                @click="setColorMode('dark')"
              >
                <Moon class="h-3.5 w-3.5" />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                class="h-7 w-7"
                :class="colorMode === 'system' && 'bg-accent'"
                @click="setColorMode('system')"
              >
                <Monitor class="h-3.5 w-3.5" />
              </Button>
            </div>
            <Separator class="my-1" />
            <Button
              variant="ghost"
              class="w-full justify-start px-2 py-1 h-auto text-[13px] font-normal"
              @click="handleLogout"
            >
              <LogOut class="mr-2 h-3.5 w-3.5" />
              <span>Log out</span>
            </Button>
          </PopoverContent>
        </Popover>
      </div>
    </aside>

    <!-- Main content -->
    <main class="flex-1 overflow-hidden">
      <RouterView />
    </main>
  </div>
</template>
